import {test} from 'node:test';import assert from 'node:assert/strict';import {Store} from '../src/lib/db';import {runRepositoryJob} from '../src/lib/repository/job';
function setup(flags:{dependencyAudit?:boolean;runtimeSecurity?:boolean}={}){const s=new Store(':memory:'),u=s.createUser('a@example.com','hash'),p=s.createProject(u.id,'Site','https://example.com/');s.linkRepository(u.id,p.id,{owner:'acme',name:'site',branch:'main',private:false},'');if(flags.runtimeSecurity)s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{kind:'repository',...flags});return {s,u,p,job:s.claimJob()!};}
const lock=JSON.stringify({lockfileVersion:3,packages:{'node_modules/example':{version:'1.0.0'}}}),snapshot={commit:'a'.repeat(40),tree:'b'.repeat(40),truncated:false,excluded:0,files:[{path:'package-lock.json',sha:'c'.repeat(40),mode:'100644',size:lock.length}]};
test('repository job runs opted-in OSV and records advisory evidence and query time',async()=>{
 const {s,u,job}=setup({dependencyAudit:true});let calls=0;
 await runRepositoryJob(s,job,{reader:{snapshot:async()=>snapshot,blob:async()=>lock},osvTransport:async url=>{calls++;return url.endsWith('querybatch')?{results:[{vulns:[{id:'GHSA-aaaa-bbbb-cccc'}]}]}:{id:'GHSA-aaaa-bbbb-cccc',database_specific:{severity:'HIGH'},summary:'Fixture advisory'};}});
 const r=s.ownedScan(u.id,job.id)!.result!;assert.ok(calls>0);assert.equal(r.dependencyAudit?.queried,1);assert.ok(r.findings.some(f=>f.rule.startsWith('repo.osv.')&&f.severity==='high'));assert.ok(!r.checks?.some(c=>c.rule==='repo.dependencies-cve'&&c.status==='unavailable'));s.close();
});
test('OSV opt-out sends no dependency data and states the configuration reason',async()=>{
 const {s,u,job}=setup();let calls=0;await runRepositoryJob(s,job,{reader:{snapshot:async()=>snapshot,blob:async()=>lock},osvTransport:async()=>{calls++;return {};}});assert.equal(calls,0);const c=s.ownedScan(u.id,job.id)!.result?.checks?.find(c=>c.rule==='repo.dependencies-cve');assert.equal(c?.unavailableReason,'configuration_required');s.close();
});
test('runtime opt-in requires domain verification and collects only the owned project origin',async()=>{
 const {s,u,p,job}=setup({runtimeSecurity:true});let collected='';await runRepositoryJob(s,job,{reader:{snapshot:async()=>snapshot,blob:async()=>lock},runtimeCollect:async(url,origin)=>{collected=url;assert.equal(origin,'https://example.com');return {url,status:200,headers:{'content-type':'text/html'},body:'<html></html>',bytes:13,elapsedMs:1};}});assert.equal(collected,p.url);assert.ok(s.ownedScan(u.id,job.id)!.result?.checks?.some(c=>c.rule==='security.https'));s.close();
 const t=setup();t.s.cancelScan(t.u.id,t.job.id);assert.throws(()=>t.s.queueScan(t.u.id,t.p.id,{kind:'repository',runtimeSecurity:true}));t.s.close();
});
test('a skipped lockfile makes dependency inventory partial even when collected versions have no advisories',async()=>{
 const {s,u,job}=setup({dependencyAudit:true});await runRepositoryJob(s,job,{maxFiles:1,reader:{snapshot:async()=>({...snapshot,files:[snapshot.files[0],{...snapshot.files[0],path:'other/package-lock.json'}]}),blob:async()=>lock},osvTransport:async()=>({results:[{}]})});const r=s.ownedScan(u.id,job.id)!.result!;assert.equal(r.dependencyAudit?.status,'partial');assert.ok(r.checks?.some(c=>c.rule==='repo.dependencies-cve'&&c.status==='unavailable'));s.close();
});
test('expired job lease blocks runtime requests and cannot be revived by renewal/progress',async()=>{
 const {runRuntimeSecurity}=await import('../src/lib/repository/runtime-security');const {s,u,job}=setup({runtimeSecurity:true});s.db.prepare('UPDATE scans SET lease_until=1 WHERE id=?').run(job.id);let calls=0;await assert.rejects(runRuntimeSecurity(s,job,undefined,async url=>{calls++;return {url,status:200,headers:{},body:'',bytes:0,elapsedMs:1};}));assert.equal(calls,0);s.renewJobLease(job.id);assert.equal(s.isRunning(job.id),false);const previous=s.ownedScan(u.id,job.id)!.stage;s.progress(job.id,'must not revive',{findings:[],checks:[],coverage:[],services:[],pages:[],scope:'',engine:'',errors:[]});assert.equal(s.ownedScan(u.id,job.id)!.stage,previous);s.close();
});
test('expired website verification blocks runtime collection after repository analysis',async()=>{
 const {s,u,p,job}=setup({runtimeSecurity:true});s.db.prepare('UPDATE projects SET verified_until=1 WHERE id=?').run(p.id);let calls=0;await runRepositoryJob(s,job,{reader:{snapshot:async()=>snapshot,blob:async()=>lock},runtimeCollect:async url=>{calls++;return {url,status:200,headers:{},body:'',bytes:0,elapsedMs:1};}});assert.equal(calls,0);assert.equal(s.ownedScan(u.id,job.id)?.result?.runtimeSecurity?.status,'unavailable');s.close();
});
test('cancellation aborts an active OSV request and never publishes final success',async()=>{
 const {s,u,job}=setup({dependencyAudit:true});let aborted=false;await runRepositoryJob(s,job,{pollMs:5,reader:{snapshot:async()=>snapshot,blob:async()=>lock},osvTransport:async(_url,options)=>{setTimeout(()=>s.cancelScan(u.id,job.id),10);return new Promise((_resolve,reject)=>options.signal!.addEventListener('abort',()=>{aborted=true;reject(new Error('aborted'));},{once:true}));}});assert.equal(aborted,true);assert.equal(s.ownedScan(u.id,job.id)?.status,'cancelled');s.close();
});
