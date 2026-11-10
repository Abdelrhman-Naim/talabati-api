import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Store} from '../src/lib/db';
import {runRepositoryJob} from '../src/lib/repository/job';
import {createHash} from 'node:crypto';
function setup(){const s=new Store(':memory:'),u=s.createUser('a@example.com','hash'),p=s.createProject(u.id,'Repo','https://example.com/');s.linkRepository(u.id,p.id,{owner:'acme',name:'course',branch:'main',private:false},'');s.queueScan(u.id,p.id,{kind:'repository'});return {s,u,p,job:s.claimJob()!};}
const code='const a=1;\neval(input);',sha=createHash('sha1').update('blob '+Buffer.byteLength(code)+'\0'+code).digest('hex');
const snapshot={commit:'a'.repeat(40),tree:'b'.repeat(40),truncated:false,excluded:1,files:[{path:'src/a.ts',sha,size:code.length,mode:'100644'},{path:'node_modules/a.js',sha,size:1,mode:'100644'}]};
test('deep worker persists real file findings, immutable source links, coverage and unavailable runtime checks',async()=>{
 const {s,u,job}=setup();await runRepositoryJob(s,job,{reader:{snapshot:async()=>snapshot,blob:async()=>code}});
 const scan=s.ownedScan(u.id,job.id)!;assert.equal(scan.status,'completed');assert.equal(scan.result?.repository?.analyzed,1);assert.equal(scan.result?.repository?.excluded,2);assert.equal(scan.result?.repository?.commit,snapshot.commit);assert.ok(scan.result?.findings.some(f=>f.file==='src/a.ts'&&f.line===2));assert.ok(!JSON.stringify(scan.result).includes(code));assert.ok(scan.result?.checks?.some(c=>c.rule==='repo.runtime'&&c.status==='unavailable'));s.close();
});
test('truncated discovery and file limits remain partial with pending count',async()=>{
 const {s,u,job}=setup();await runRepositoryJob(s,job,{maxFiles:1,reader:{snapshot:async()=>({...snapshot,truncated:true,files:[snapshot.files[0],{...snapshot.files[0],path:'src/b.ts'}]}),blob:async()=>code}});
 const scan=s.ownedScan(u.id,job.id)!;assert.equal(scan.status,'partial');assert.equal(scan.result?.repository?.pending,1);assert.equal(scan.result?.repository?.truncated,true);s.close();
});
test('cancellation aborts in-flight repository reads without publishing completion',async()=>{
 const {s,u,job}=setup();let signal:AbortSignal|undefined;
 await runRepositoryJob(s,job,{pollMs:5,reader:{snapshot:async(_branch,sig)=>{signal=sig;setTimeout(()=>s.cancelScan(u.id,job.id),10);return new Promise((_resolve,reject)=>sig!.addEventListener('abort',()=>reject(new Error('aborted')),{once:true}));},blob:async()=>code}});
 assert.equal(signal?.aborted,true);assert.equal(s.ownedScan(u.id,job.id)?.status,'cancelled');s.close();
});
test('repository request timeout ends failed rather than leaving a running scan',async()=>{
 const {s,u,job}=setup();await runRepositoryJob(s,job,{requestMs:10,reader:{snapshot:async()=>new Promise(()=>{}),blob:async()=>code}});assert.equal(s.ownedScan(u.id,job.id)?.status,'failed');s.close();
});
test('oversized eligible files are excluded without blocking later valid sources',async()=>{
 const {s,u,job}=setup();let readCount=0;
 await runRepositoryJob(s,job,{reader:{snapshot:async()=>({...snapshot,files:[{...snapshot.files[0],path:'package-lock.json',size:25*1024*1024},snapshot.files[0]]}),blob:async()=>{readCount++;return code;}}});
 const r=s.ownedScan(u.id,job.id)!.result!;assert.equal(readCount,1);assert.equal(r.repository?.analyzed,1);assert.equal(r.repository?.pending,0);assert.ok(r.repository?.files.some(f=>f.file==='package-lock.json'&&f.status==='excluded'));s.close();
});
test('unsupported text is excluded and collection continues to valid source',async()=>{
 const {UnsupportedRepositoryFile}=await import('../src/lib/repository/github');const {s,u,job}=setup();
 await runRepositoryJob(s,job,{reader:{snapshot:async()=>({...snapshot,files:[{...snapshot.files[0],path:'binary.key'},snapshot.files[0]]}),blob:async f=>{if(f.path==='binary.key')throw new UnsupportedRepositoryFile();return code;}}});
 const r=s.ownedScan(u.id,job.id)!.result!;assert.equal(r.repository?.analyzed,1);assert.equal(r.repository?.pending,0);assert.ok(r.repository?.files.some(f=>f.file==='binary.key'&&f.status==='excluded'));assert.ok(!r.errors.some(e=>e.includes('التوكن')));s.close();
});
