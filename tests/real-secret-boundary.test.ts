import {test} from 'node:test';import assert from 'node:assert/strict';import {mkdtempSync,rmSync,readdirSync,readFileSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';import {createHash} from 'node:crypto';import {NextRequest} from 'next/server';
import {getStore} from '../src/lib/db';import {runRepositoryJob} from '../src/lib/repository/job';import {GET} from '../src/app/api/[...path]/route';
// Deliberately fake provider-format values. Exercise real worker, real Store/SQLite,
// and the application's authenticated GET handler; no simulated API response.
test('real scan path persists normalized findings and exposes no full secret to logs, DB or API',async(t)=>{
 const oldDir=process.env.DATA_DIR,dir=mkdtempSync(join(tmpdir(),'aegis-boundary-'));process.env.DATA_DIR=dir;
 const secrets=['sk_live_1234567890abcdef','sk-proj-'+'a'.repeat(40),'ghp_'+'b'.repeat(30),'AKIAABCDEFGHIJKLMNOP'];const body=secrets.map((s,i)=>'export const credential'+i+'='+JSON.stringify(s)+';').join('\n');
 const sourceFile='src/'+secrets[0]+'.ts',sha=createHash('sha1').update('blob '+Buffer.byteLength(body)+'\0'+body).digest('hex'),consoleLines:string[]=[];
 for(const method of ['log','warn','error','info','debug'] as const)t.mock.method(console,method,(...args:unknown[])=>{consoleLines.push(args.map(String).join(' '));});
 const streamLines:string[]=[];for(const stream of [process.stdout,process.stderr]){const write=stream.write.bind(stream);t.mock.method(stream,'write',(chunk:unknown,...args:unknown[])=>{streamLines.push(Buffer.isBuffer(chunk)?chunk.toString('utf8'):String(chunk));return Reflect.apply(write,stream,[chunk,...args]);});}
 const store=getStore(),user=store.createUser('secret-boundary@example.com','fixture-password-hash'),project=store.createProject(user.id,'Boundary','https://example.com');
 try{store.linkRepository(user.id,project.id,{owner:'fixture',name:'boundary',branch:'main',private:false},'');store.queueScan(user.id,project.id,{kind:'repository'});const job=store.claimJob()!;
  const snapshots:string[]=[],publish=store.progress.bind(store);store.progress=(id,stage,result)=>{snapshots.push(JSON.stringify({stage,result}));publish(id,stage,result);};
  await runRepositoryJob(store,job,{reader:{snapshot:async()=>({commit:'a'.repeat(40),tree:'b'.repeat(40),truncated:false,excluded:0,files:[{path:sourceFile,sha,size:Buffer.byteLength(body),mode:'100644'}]}),blob:async()=>body},apiHttpTransport:async()=>{throw new Error('Unexpected external API request in fixture');}});
  const scan=store.ownedScan(user.id,job.id)!;assert.equal(scan.status,'completed');assert.ok(scan.result?.normalizedFindings?.some(f=>f.rule==='repo.secret'));assert.equal(scan.result?.findingNormalization?.version,1);assert.ok(snapshots.length>0);assert.ok(scan.result!.events!.length>0);
  const token=store.createSession(user.id),response=await GET(new NextRequest('http://localhost/api/state',{headers:{cookie:'aegis_session='+token}}),{params:Promise.resolve({path:['state']})});assert.ok(response);assert.equal(response.status,200);const apiBody=await response.text();assert.ok(JSON.parse(apiBody).scans.some((s:{id:string})=>s.id===job.id));
  const dbDump=JSON.stringify(store.db.prepare('SELECT * FROM scans').all());const logs=JSON.stringify({consoleLines,streamLines,events:scan.result!.events,snapshots});
  for(const secret of secrets){assert.ok(!apiBody.includes(secret));assert.ok(!dbDump.includes(secret));assert.ok(!logs.includes(secret));for(const file of readdirSync(dir))assert.ok(!readFileSync(join(dir,file)).includes(Buffer.from(secret)));}
 }finally{store.close();rmSync(dir,{recursive:true,force:true});if(oldDir===undefined)delete process.env.DATA_DIR;else process.env.DATA_DIR=oldDir;}
});
