import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {NextRequest} from 'next/server';
import {GET,POST,DELETE} from '../src/app/api/[...path]/route.ts';
const directory=mkdtempSync(join(tmpdir(),'aegis-api-'));process.env.DATA_DIR=directory;
test('route integration: auth, CSRF, owner boundaries, verified scope gate, export and logout',async()=>{
 const base='http://localhost:3000';let cookie='';
 async function call(path:string,method='GET',data?:unknown,headers:Record<string,string>={}){
  const req=new NextRequest(base+'/api/'+path,{method,headers:{...(data!==undefined?{'Content-Type':'application/json',Origin:base}:{}),...(cookie?{Cookie:cookie}:{}),...headers},body:data!==undefined?JSON.stringify(data):undefined});
  const fn=method==='GET'?GET:method==='DELETE'?DELETE:POST;const r=(await fn(req,{params:Promise.resolve({path:path.split('/')})}))!;
  const c=r.headers.get('set-cookie');if(c)cookie=c.split(';')[0];return {status:r.status,data:await r.json()};
 }
 try{
  assert.equal((await call('state')).status,401);
  assert.equal((await call('auth/register','POST',{email:'a@example.com',password:'test-password-123'},{Origin:'https://evil.example'})).status,403);
  assert.equal((await call('auth/register','POST',{email:'a@example.com',password:'test-password-123'})).status,200);const first=cookie;
  const p=await call('projects','POST',{name:'Test',url:'https://example.com/'});assert.equal(p.status,200);
  assert.equal((await call('projects/'+p.data.project.id+'/scan','POST',{authorized:true})).status,400);
  assert.equal((await call('projects','POST',{name:'Secret URL',url:'https://example.com/sk_live_abcdefghijklmnop'})).status,400);
  const {getStore}=await import('../src/lib/db.ts');getStore().verifyProject(p.data.project.owner_id,p.data.project.id);
  const full=await call('projects/'+p.data.project.id+'/scan','POST',{authorized:true,maxPages:40});assert.equal(full.status,200);assert.equal(full.data.scan.crawlOptions.mode,'full');assert.equal(full.data.scan.crawlOptions.maxPages,40);
  assert.equal((await call('scans/'+full.data.scan.id+'/cancel','POST',{})).status,200);
  assert.equal((await call('projects/'+p.data.project.id+'/scan','POST',{authorized:true,mode:'invalid'})).status,400);
  assert.equal((await call(`projects/${p.data.project.id}/repository`,'POST',{url:'https://evil.example/a/b',authorized:true})).status,400);
  assert.equal((await call(`projects/${p.data.project.id}/repository`,'POST',{url:'https://github.com/a/b',token:'bad-token',authorized:true})).status,400);
  const link=getStore().linkRepository(p.data.project.owner_id,p.data.project.id,{owner:'acme',name:'course',branch:'main',private:true},'github_pat_example_private_value123456789');
  const repoResponse=await call(`projects/${p.data.project.id}/repository`);assert.equal(repoResponse.status,200);assert.equal(repoResponse.data.repository.hasToken,true);assert.ok(!JSON.stringify(repoResponse).includes('github_pat_'));
  const deep=await call(`projects/${p.data.project.id}/scan`,'POST',{authorized:true,kind:'repository',dependencyAudit:true,runtimeSecurity:true});assert.equal(deep.status,200);assert.equal(deep.data.scan.repository.id,link.id);assert.equal(deep.data.scan.dependencyAudit,true);assert.equal(deep.data.scan.runtimeSecurity,true);
  assert.equal((await call(`projects/${p.data.project.id}/repository`,'DELETE',{})).status,200);assert.equal((await call('scans/'+deep.data.scan.id)).data.scan.status,'cancelled');
  const apiSettings={origin:'https://api.example.com',proofPath:'/.well-known/aegis-audit.txt',kind:'api',tokenA:'fixture-token-A',tokenB:'fixture-token-B',publicKey:'',pathA:'/fixtures/a',pathB:'/fixtures/b',markerA:'aegis-test-owner-a',markerB:'aegis-test-owner-b',staging:true};
  const cfg=await call(`projects/${p.data.project.id}/api-tests`,'POST',apiSettings);assert.equal(cfg.status,200);assert.ok(!JSON.stringify(cfg).includes(apiSettings.tokenA));
  const meta=await call('state');assert.equal(meta.data.apiConfigs.length,1);assert.ok(!JSON.stringify(meta).includes(apiSettings.tokenB));
  assert.equal((await call(`projects/${p.data.project.id}/api-tests`,'POST',apiSettings,{Origin:'https://evil.example'})).status,403);
  const demo=await call('demo','POST',{});assert.equal(demo.status,200);const id=demo.data.scan.id;
  assert.equal((await call('scans/'+id+'/export')).status,200);assert.equal((await call(`scans/${id}/checks`)).data.checks.length,demo.data.scan.result.checks.length);const f=demo.data.scan.result.findings[0];
  const whole=await call(`scans/${id}/prompt`,'POST',{findingIds:[f.id]});assert.equal(whole.status,200);assert.ok(whole.data.prompt.includes(f.title));
  assert.equal((await call(`scans/${id}/prompt`,'POST',{findingIds:['unknown']})).status,400);
  const prompt=await call(`scans/${id}/findings/${f.id}/prompt`,'POST',{});assert.equal(prompt.status,200);assert.ok(prompt.data.prompt.includes(f.title));
  cookie='';assert.equal((await call('auth/register','POST',{email:'b@example.com',password:'test-password-456'})).status,200);
  assert.equal((await call('scans/'+id)).status,404);assert.equal((await call(`scans/${id}/prompt`,'POST',{})).status,404);assert.equal((await call('projects/'+p.data.project.id,'DELETE',{})).status,404);
  assert.equal((await call(`projects/${p.data.project.id}/repository`)).status,404);
  assert.equal((await call(`projects/${p.data.project.id}/api-tests`)).status,404);
  assert.equal((await call(`projects/${p.data.project.id}/api-tests`,'POST',{})).status,404);
  assert.equal((await call(`scans/${id}/checks`)).status,404);
  cookie=first;assert.equal((await call('auth/logout','POST',{})).status,200);assert.equal((await call('state')).status,401);
 }finally{const {getStore}=await import('../src/lib/db.ts');getStore().close();rmSync(directory,{recursive:true,force:true});}
});
