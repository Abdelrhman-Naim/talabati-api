import {test} from 'node:test';
import assert from 'node:assert/strict';
import {parseRepository,GitHubReader} from '../src/lib/repository/github';
import {encryptToken,decryptToken} from '../src/lib/repository/vault';
import {analyzeSource,eligibleSource} from '../src/lib/repository/analyzer';
import {createHash,randomBytes} from 'node:crypto';
test('GitHub binding accepts one exact repository and rejects alternate hosts or URL credentials',()=>{
 assert.deepEqual(parseRepository('https://github.com/acme/course.git'),{owner:'acme',name:'course'});
 for(const value of ['https://evil.example/acme/course','https://github.com@evil.example/acme/course','https://github.com/acme/course/tree/main','https://github.com/acme/course?token=secret','https://github.com/a/../b','https://user:pass@github.com/a/b'])assert.throws(()=>parseRepository(value));
});
test('repository tokens are authenticated encrypted and bound to their owner/link',()=>{
 const key=randomBytes(32),token='github_pat_private_test_value_1234567890';const sealed=encryptToken(token,key,'owner/project/link');
 assert.ok(!sealed.includes(token));assert.equal(decryptToken(sealed,key,'owner/project/link'),token);
 assert.throws(()=>decryptToken(sealed,key,'other/project/link'));assert.throws(()=>decryptToken(sealed,randomBytes(32),'owner/project/link'));
});
test('source findings include file/line and hide secrets; public Supabase keys remain public',()=>{
 const source='const publicKey="sb_publishable_abcdefghijk";\nconst secret="sb_secret_abcdefghijklmno";\neval(input);';
 const out=analyzeSource('src/a.ts',source,'https://github.com/acme/course/blob/'+'a'.repeat(40)+'/src/a.ts');
 const secret=out.findings.find(f=>f.rule==='repo.secret')!;assert.equal(secret.line,2);assert.equal(secret.file,'src/a.ts');assert.ok(!JSON.stringify(out).includes('sb_secret_abcdefghijklmno'));
 assert.ok(out.findings.some(f=>f.rule==='repo.eval'&&f.line===3));assert.equal(secret.security?.basis,'indicator');
 assert.equal(analyzeSource('src/public.ts','const key="sb_publishable_abcdefghijk";','https://github.com/a/b').findings.length,0);
});
test('analyzer excludes dependencies/builds/binaries and marks risky static patterns as indicators',()=>{
 for(const p of ['node_modules/a/index.js','.next/static/a.js','x.png','vendor/a.php'])assert.equal(eligibleSource(p),false);
 assert.equal(eligibleSource('supabase/migrations/a.sql'),true);assert.equal(eligibleSource('.env.production'),true);
 const out=analyzeSource('supabase/migrations/a.sql','ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;','https://github.com/a/b');
 assert.ok(out.findings.some(f=>f.rule==='repo.rls-disabled'));
});
test('GitHub reads immutable commit/tree/blob and never follows returned download URLs',async()=>{
 const source='eval(input);',sha=createHash('sha1').update('blob '+Buffer.byteLength(source)+'\0'+source).digest('hex'),commit='a'.repeat(40),tree='b'.repeat(40),calls:string[]=[];
 const reader=new GitHubReader({owner:'acme',name:'course'},'',async(url)=>{calls.push(url);let data:unknown;
 if(url.endsWith('/commits/feature%2Fone'))data={sha:commit,commit:{tree:{sha:tree}}};
 else if(url.includes('/git/trees/'))data={truncated:false,tree:[{path:'src/a.ts',mode:'100644',type:'blob',sha,size:source.length}]};
 else data={encoding:'base64',size:source.length,content:Buffer.from(source).toString('base64')};
 return {status:200,headers:{},body:JSON.stringify(data),url,bytes:1,elapsedMs:1};});
 const snapshot=await reader.snapshot('feature/one');assert.equal(snapshot.commit,commit);const content=await reader.blob(snapshot.files[0]);assert.equal(content,source);
 assert.ok(calls.every(url=>url.startsWith('https://api.github.com/repos/acme/course/')));assert.ok(calls.some(url=>url.includes(tree)));
});
test('GitHub redirects/rate limits fail safely without leaking credentials',async()=>{
 for(const status of [301,403,429]){
 const reader=new GitHubReader({owner:'a',name:'b'},'private-token',async(url)=>({url,status,headers:{},body:'private-token',bytes:1,elapsedMs:1}));
 await assert.rejects(reader.snapshot('main'),e=>e instanceof Error&&!e.message.includes('private-token'));
 }
});
test('inline HTML JavaScript is analyzed and unsupported language coverage is explicit',()=>{
 const html=analyzeSource('index.html','<script>eval(userInput);</script>','https://github.com/a/b');assert.ok(html.findings.some(f=>f.rule==='repo.eval'));
 const go=analyzeSource('main.go','package main','https://github.com/a/b');assert.ok(go.checks.some(c=>c.rule==='repo.language-rules'&&c.status==='unavailable'));
 const env=analyzeSource('.env','NODE_TLS_REJECT_UNAUTHORIZED=0','https://github.com/a/b');assert.ok(env.findings.some(f=>f.rule==='repo.tls-bypass'));
});
test('repository credentials require HTTPS or a loopback development origin',async()=>{
 const {credentialOriginAllowed}=await import('../src/lib/repository/vault');
 assert.equal(credentialOriginAllowed('http://audit.example'),false);assert.equal(credentialOriginAllowed('https://audit.example'),true);assert.equal(credentialOriginAllowed('http://localhost:3000'),true);assert.equal(credentialOriginAllowed('http://localhost.evil.example'),false);
});
