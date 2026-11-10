import test from 'node:test';
import assert from 'node:assert/strict';
import {Store} from '../src/lib/db.ts';
import {hashPassword,verifyPassword} from '../src/lib/auth.ts';
import {runJob} from '../src/lib/jobs.ts';
import {scoreReport,SCORE_VERSION} from '../src/lib/scoring.ts';

test('passwords are salted and invalid or changed passwords are rejected',()=>{
  const hash=hashPassword('test-password-123');assert.notEqual(hash,hashPassword('test-password-123'));
  assert.equal(verifyPassword('test-password-123',hash),true);assert.equal(verifyPassword('wrong-password',hash),false);
});
test('projects cannot be read by another owner and unverified scans are rejected',()=>{
  const s=new Store(':memory:');const a=s.createUser('a@example.com','hash');const b=s.createUser('b@example.com','hash');
  const p=s.createProject(a.id,'Academy','https://example.com/');assert.equal(s.ownedProject(b.id,p.id),null);
  assert.throws(()=>s.queueScan(a.id,p.id,{mode:'quick'}),/ملكية/);s.close();
});
test('sessions store hashes, expire, and can be revoked',()=>{
  const s=new Store(':memory:');const u=s.createUser('a@example.com','hash');const token=s.createSession(u.id,Date.now()+10000);
  assert.equal(s.sessionUser(token)?.id,u.id);s.deleteSession(token);assert.equal(s.sessionUser(token),null);
  const old=s.createSession(u.id,Date.now()-1);assert.equal(s.sessionUser(old),null);s.close();
});
test('durable job claims only once and cancellation prevents final success',()=>{
  const s=new Store(':memory:');const u=s.createUser('a@example.com','hash');const p=s.createProject(u.id,'Academy','https://example.com/');s.verifyProject(u.id,p.id);
  const scan=s.queueScan(u.id,p.id,{mode:'quick'});assert.equal(s.claimJob()?.id,scan.id);assert.equal(s.claimJob(),null);
  s.cancelScan(u.id,scan.id);s.finishScan(scan.id,'completed',{findings:[],services:[],pages:[],coverage:[],errors:[],scope:p.url,engine:'test'});
  assert.equal(s.ownedScan(u.id,scan.id)?.status,'cancelled');s.close();
});
test('collection failure is failed, not an empty successful report',async()=>{
  const s=new Store(':memory:');const u=s.createUser('a@example.com','hash');const p=s.createProject(u.id,'Academy','https://example.com/');s.verifyProject(u.id,p.id);
  s.queueScan(u.id,p.id,{mode:'quick'});const job=s.claimJob()!;await runJob(s,job,async()=>{throw new Error('collection denied');},0);
  assert.equal(s.ownedScan(u.id,job.id)?.status,'failed');s.close();
});
test('expired AI leases can be reclaimed but active leases cannot',()=>{
  const s=new Store(':memory:');assert.equal(s.acquireLock('ai','one',Date.now()+10000),true);assert.equal(s.acquireLock('ai','two',Date.now()+10000),false);
  s.releaseLock('ai','wrong');assert.equal(s.acquireLock('ai','two',Date.now()+10000),false);s.releaseLock('ai','one');assert.equal(s.acquireLock('ai','two',Date.now()+10000),true);s.close();
});
test('worker persists evidence from an authorized fixture and never calls discovered external API',async()=>{
  const s=new Store(':memory:');const u=s.createUser('a@example.com','hash');const p=s.createProject(u.id,'Academy','https://example.com/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'quick'});const job=s.claimJob()!;
  const calls:string[]=[];await runJob(s,job,async url=>{calls.push(url);return {url,status:200,headers:{'content-type':'text/html'},body:'<html><script>const api="https://outside.supabase.co/rest/v1/courses"</script></html>',elapsedMs:1,bytes:100};},0,{apiHttpTransport:async url=>({url,status:204,headers:{},body:'',bytes:0,elapsedMs:1})});
  const done=s.ownedScan(u.id,job.id)!;assert.equal(done.status,'completed');assert.ok(done.result?.findings.some(f=>f.rule==='seo.title'));assert.equal(done.result?.services[0].origin,'https://outside.supabase.co');assert.deepEqual(calls,['https://example.com/']);
  assert.ok(done.result?.checks?.some(c=>c.rule==='technical.http'&&c.status==='pass'));
  assert.equal(done.result?.scoreVersion,SCORE_VERSION);s.close();
});
for(const failure of ['404','throw'] as const)test(`missing JavaScript (${failure}) stays unavailable and cannot earn a secret-check pass`,async()=>{
 const s=new Store(':memory:');const u=s.createUser('a@example.com','hash'),p=s.createProject(u.id,'A','https://example.com/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'quick'});const job=s.claimJob()!;
 await runJob(s,job,async url=>{if(url.endsWith('/missing.js')){if(failure==='throw')throw new Error('failed asset');return {url,status:404,headers:{'content-type':'text/html'},body:'not found',bytes:9,elapsedMs:10};}return {url,status:200,headers:{'content-type':'text/html'},body:'<script src="/missing.js"></script>',bytes:35,elapsedMs:10};},0);
 const result=s.ownedScan(u.id,job.id)!.result!;assert.equal(result.collection?.scriptSuccesses,0);const missing=result.checks!.find(c=>c.rule==='security.secret'&&c.url.endsWith('/missing.js'));assert.equal(missing?.status,'unavailable');assert.ok(result.errors.length>0);s.close();
});
test('redirect aliases cannot duplicate page checks or diverge ledger and scoring denominators',async()=>{
 const s=new Store(':memory:');const u=s.createUser('a@example.com','hash'),p=s.createProject(u.id,'A','https://example.com/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'quick'});const job=s.claimJob()!;let requests=0;
 await runJob(s,job,async()=>{requests++;return {url:'https://example.com/home',status:200,headers:{'content-type':'text/html'},body:'<a href="/home">Home</a>',bytes:25,elapsedMs:10};},0);
 const result=s.ownedScan(u.id,job.id)!.result!,summary=scoreReport(result);assert.equal(requests,1);assert.equal(result.pages.length,1);assert.equal(result.checks!.length,summary.overall.planned+summary.overall.notApplicable);s.close();
});
test('new jobs cannot be consumed by a legacy queued-only worker',()=>{
 const s=new Store(':memory:');const u=s.createUser('a@example.com','hash'),p=s.createProject(u.id,'A','https://example.com/');s.verifyProject(u.id,p.id);const scan=s.queueScan(u.id,p.id,{mode:'quick'});
 assert.equal(s.db.prepare("SELECT count(*) AS n FROM scans WHERE status IN ('queued','queued_v3','queued_v5','queued_v6','queued_v7')").get()!.n,0);
 assert.equal(scan.status,'queued');assert.equal(s.claimJob()?.id,scan.id);s.close();
});
test('worker identity and periodic lease renewal are persisted independently from page progress',()=>{
 const s=new Store(':memory:');const u=s.createUser('a@example.com','hash'),p=s.createProject(u.id,'A','https://example.com/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'quick'});const job=s.claimJob()!;
 s.db.prepare('UPDATE scans SET lease_until=? WHERE id=?').run(Date.now()+1000,job.id);s.renewJobLease(job.id);assert.equal(s.claimJob(),null);assert.equal(s.ownedScan(u.id,job.id)?.status,'running');
 s.heartbeat('browser');assert.equal(s.workerInfo().version,'0.12.0');assert.equal(s.workerInfo().mode,'browser');s.close();
});
test('stalled page fetch finishes within request budget instead of leaving scan running',async()=>{
 const s=new Store(':memory:'),u=s.createUser('budget@example.com','hash'),p=s.createProject(u.id,'A','https://example.com/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'quick'});const job=s.claimJob()!;const started=Date.now();let aborted=false;
 await runJob(s,job,(_url,_origin,signal)=>{signal?.addEventListener('abort',()=>{aborted=true;});return new Promise(()=>{});},0,{budgetMs:50,requestTimeoutMs:20});
 assert.equal(aborted,true);
 assert.ok(Date.now()-started<1000);assert.equal(s.ownedScan(u.id,job.id)?.status,'failed');assert.match(s.ownedScan(u.id,job.id)?.result?.errors.join(' ')??'',/مهلة/);s.close();
});
test('scan event log records actual fetch and analysis in order without invented completion',async()=>{
 const s=new Store(':memory:'),u=s.createUser('events@example.com','hash'),p=s.createProject(u.id,'A','https://example.com/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'quick'});const job=s.claimJob()!;
 await runJob(s,job,async url=>{
  const live=s.ownedScan(u.id,job.id)!;assert.equal(live.result?.events?.at(-1)?.phase,'fetch');
  return {url,status:200,headers:{'content-type':'text/html'},body:'<h1>Test</h1>',bytes:13,elapsedMs:2};
 },0);
 const events=s.ownedScan(u.id,job.id)?.result?.events??[];
 assert.ok(events.some(e=>e.phase==='analyze'&&e.status==='done'));assert.equal(events.at(-1)?.phase,'complete');
 assert.ok(events.every(e=>Number.isFinite(e.at)));s.close();
});
test('collector phase messages reach the persisted activity log while the page is loading',async()=>{
 const s=new Store(':memory:'),u=s.createUser('phase@example.com','hash'),p=s.createProject(u.id,'A','https://example.com/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'quick'});const job=s.claimJob()!;
 await runJob(s,job,async(url,_origin,_signal,progress)=>{
  progress?.('تشغيل axe على DOM');
  assert.ok(s.ownedScan(u.id,job.id)?.result?.events?.some(e=>e.message==='تشغيل axe على DOM'));
  return {url,status:200,headers:{'content-type':'text/html'},body:'<h1>Test</h1>',bytes:13,elapsedMs:2};
 },0);
 assert.ok(s.ownedScan(u.id,job.id)?.result?.events?.some(e=>e.message==='تشغيل axe على DOM'));s.close();
});
