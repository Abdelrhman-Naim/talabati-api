import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Store} from '../src/lib/db';
test('repository binding isolates owners, encrypts credentials, and queues deep scans without changing URL verification',()=>{
 const store=new Store(':memory:'),a=store.createUser('a@example.com','hash'),b=store.createUser('b@example.com','hash'),p=store.createProject(a.id,'Repo','https://example.com/'),token='github_pat_example_private_value123456789';
 assert.throws(()=>store.linkRepository(b.id,p.id,{owner:'acme',name:'course',branch:'main',private:true},token));
 const link=store.linkRepository(a.id,p.id,{owner:'acme',name:'course',branch:'main',private:true},token);
 assert.ok(!JSON.stringify(link).includes(token));assert.equal(store.repository(b.id,p.id),null);
 assert.ok(!JSON.stringify(store.db.prepare('SELECT * FROM repository_links').all()).includes(token));
 assert.throws(()=>store.queueScan(a.id,p.id));
 const job=store.queueScan(a.id,p.id,{kind:'repository'});assert.equal(job.kind,'repository');assert.equal(job.repository?.id,link.id);
 assert.equal(store.repositoryCredential(a.id,p.id,link.id),token);assert.throws(()=>store.repositoryCredential(b.id,p.id,link.id));
 assert.equal(store.db.prepare("SELECT count(*) AS n FROM scans WHERE status='queued_v6'").get()!.n,0);
 store.claimJob();assert.throws(()=>store.linkRepository(a.id,p.id,{owner:'acme',name:'other',branch:'main',private:false},''));
 store.unlinkRepository(a.id,p.id);assert.equal(store.ownedScan(a.id,job.id)?.status,'cancelled');assert.equal(store.repository(a.id,p.id),null);store.close();
});
test('encrypted binding survives a process-style reopen with its private persisted key',async()=>{
 const {mkdtempSync,rmSync,statSync}=await import('node:fs');const {tmpdir}=await import('node:os');const {join}=await import('node:path');const directory=mkdtempSync(join(tmpdir(),'aegis-repo-key-'));
 try{let s=new Store(join(directory,'test.sqlite'));const u=s.createUser('persist@example.com','hash'),p=s.createProject(u.id,'Persist','https://example.com/'),token='github_pat_persistent_private_value123456789';const link=s.linkRepository(u.id,p.id,{owner:'acme',name:'course',branch:'main',private:true},token);s.close();s=new Store(join(directory,'test.sqlite'));assert.equal(s.repositoryCredential(u.id,p.id,link.id),token);if(process.platform!=='win32'){assert.equal(statSync(join(directory,'.repository-key')).mode&0o777,0o600);}s.close();}finally{try{rmSync(directory,{recursive:true,force:true,maxRetries:5,retryDelay:100});}catch{}}
});
test('binding guards and disconnect cancellation do not depend on the 100-report UI limit',()=>{
 const s=new Store(':memory:'),u=s.createUser('limit@example.com','hash'),p=s.createProject(u.id,'Limit','https://example.com/');s.linkRepository(u.id,p.id,{owner:'acme',name:'course',branch:'main',private:false},'');const scan=s.queueScan(u.id,p.id,{kind:'repository'});s.db.prepare('UPDATE scans SET created_at=0 WHERE id=?').run(scan.id);
 for(let i=0;i<100;i++)s.addDemo(u.id,p,{findings:[],services:[],coverage:[],pages:[],errors:[],scope:'fixture',engine:'fixture'});
 assert.throws(()=>s.linkRepository(u.id,p.id,{owner:'acme',name:'other',branch:'main',private:false},''));s.unlinkRepository(u.id,p.id);assert.equal(s.ownedScan(u.id,scan.id)?.status,'cancelled');s.close();
});
