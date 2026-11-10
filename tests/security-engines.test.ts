import {test} from 'node:test';import assert from 'node:assert/strict';
import {analyzeJavaScript} from '../src/lib/repository/ast';
import {parseLockfile} from '../src/lib/repository/dependencies';
import {auditDependencies} from '../src/lib/repository/osv';
test('AST ignores strings and comments but identifies actual multiline unsafe calls with lines',()=>{
 const r=analyzeJavaScript('src/a.ts','// eval(input)\nconst example="eval(input)";\neval(\n input\n);\nconst db=pool.query(`SELECT * FROM t WHERE id=${input}`);');
 assert.deepEqual(r.matches['repo.eval'],[3]);assert.deepEqual(r.matches['repo.sql-concat'],[6]);assert.equal(r.valid,true);
});
test('AST separates syntax failure from absence of findings',()=>{assert.equal(analyzeJavaScript('x.ts','const = ;').valid,false);});
test('lock parser uses installed exact versions, nested scoped names and deduplicates',()=>{
 const r=parseLockfile('package-lock.json',JSON.stringify({lockfileVersion:3,packages:{'':{name:'root',version:'1.0.0'},'node_modules/a':{version:'1.2.3',resolved:'https://registry.npmjs.org/a/-/a.tgz'},'node_modules/x/node_modules/@scope/b':{version:'2.3.4'},'node_modules/y/node_modules/a':{version:'1.2.3'},'node_modules/link':{link:true},'node_modules/range':{version:'^1.0.0'}}}));
 assert.deepEqual(r.packages.map(x=>x.name+'@'+x.version).sort(),['@scope/b@2.3.4','a@1.2.3']);assert.equal(r.incomplete,true);
 assert.throws(()=>parseLockfile('package-lock.json','{broken'));
});
test('OSV sends names/versions only and records matched advisory details without claiming exploitability',async()=>{
 const calls:{url:string;body?:string}[]=[];const packages=[{name:'example',version:'1.2.3',file:'package-lock.json',line:5}];
 const r=await auditDependencies(packages,async(url,options)=>{calls.push({url,body:options.body});return url.endsWith('querybatch')?{results:[{vulns:[{id:'GHSA-aaaa-bbbb-cccc'}]}]}:{id:'GHSA-aaaa-bbbb-cccc',summary:'Example advisory',aliases:['CVE-2099-1234'],database_specific:{severity:'HIGH'},affected:[{package:{name:'example',ecosystem:'npm'},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'1.2.4'}]}]}]};});
 assert.equal(r.status,'completed');assert.equal(r.advisories.length,1);assert.equal(r.advisories[0].severity,'high');assert.ok(calls.every(c=>c.url.startsWith('https://api.osv.dev/')));assert.ok(!calls[0].body!.includes('package-lock.json'));assert.ok(!calls[0].body!.includes('github'));
});
test('OSV pagination and API errors cannot be interpreted as a clean pass',async()=>{
 const p=[{name:'example',version:'1.0.0',file:'package-lock.json',line:1}];
 const partial=await auditDependencies(p,async()=>({results:[{next_page_token:'more'}]}));assert.equal(partial.status,'partial');
 const failed=await auditDependencies(p,async()=>{throw new Error('network');});assert.equal(failed.status,'unavailable');assert.equal(failed.queried,0);
});
test('source ledger uses AST results and JSON parsing rather than placeholder language failures',async()=>{
 const {analyzeSource}=await import('../src/lib/repository/analyzer');
 const code=analyzeSource('src/a.ts','// eval(input)\nconst label="eval(input)";','https://github.com/a/b');assert.ok(!code.findings.some(f=>f.rule==='repo.eval'));
 const json=analyzeSource('tsconfig.json','{"compilerOptions":{"strict":true}}','https://github.com/a/b');assert.ok(json.checks.some(c=>c.rule==='repo.json-valid'&&c.status==='pass'));assert.ok(!json.checks.some(c=>c.rule==='repo.language-rules'));
});
test('declaration files are parsed without emission failures and public secret comments do not become findings',async()=>{
 assert.doesNotThrow(()=>analyzeJavaScript('src/env.d.ts','interface ImportMeta { readonly env: unknown }'));
 const {analyzeSource}=await import('../src/lib/repository/analyzer');const out=analyzeSource('a.ts','// NEXT_PUBLIC_SECRET="example"\nconst a=1;','https://github.com/a/b');assert.ok(!out.findings.some(f=>f.rule==='repo.public-secret'));
});
test('OSV malformed per-package errors and malformed withdrawals never earn clean passes',async()=>{
 const p=[{name:'example',version:'1.0.0',file:'package-lock.json',line:1}];
 const malformed=await auditDependencies(p,async()=>({results:[{error:'failed'}]}));assert.notEqual(malformed.status,'completed');assert.equal(malformed.packages[0].checked,false);
 const withdrawn=await auditDependencies(p,async url=>url.endsWith('querybatch')?{results:[{vulns:[{id:'GHSA-aaaa-bbbb-cccc'}]}]}:{id:'GHSA-aaaa-bbbb-cccc',withdrawn:true});assert.notEqual(withdrawn.status,'completed');assert.equal(withdrawn.advisories.length,1);
});
test('malformed OSV pagination token values cannot become a completed clean query',async()=>{
 const p=[{name:'example',version:'1.0.0',file:'package-lock.json',line:1}];for(const token of [false,0,null]){const r=await auditDependencies(p,async()=>({results:[{next_page_token:token}]}));assert.notEqual(r.status,'completed');assert.equal(r.packages[0].checked,false);}
});
test('service transport cannot POST to arbitrary targets or send unbounded bodies',async()=>{
 const {requestResource}=await import('../src/lib/network');await assert.rejects(requestResource('https://example.com/',{method:'POST',body:'{}'}));await assert.rejects(requestResource('https://api.osv.dev/v1/querybatch',{method:'POST',body:'x'.repeat(65537)}));
});
test('JSON syntax failures remain technical findings rather than invented security vulnerabilities',async()=>{
 const {analyzeSource}=await import('../src/lib/repository/analyzer');const r=analyzeSource('config.json','{broken','https://github.com/a/b');assert.equal(r.findings.find(f=>f.rule==='repo.json-valid')?.category,'technical');
});
test('module TypeScript syntax and JSON-LD are not mistaken for invalid JSX or JavaScript',()=>{
 assert.equal(analyzeJavaScript('a.mts','const identity = <T>(value:T)=>value;').valid,true);
 assert.equal(analyzeJavaScript('a.cts','const identity = <T>(value:T)=>value;').valid,true);
 const html=analyzeJavaScript('index.html','<script type="application/ld+json">{"@type":"WebSite"}</script><script>eval(input)</script>');assert.equal(html.valid,true);assert.ok(html.matches['repo.eval']);
});
test('public environment assignments are checked even when the syntax engine cannot parse the file',async()=>{
 const {analyzeSource}=await import('../src/lib/repository/analyzer');
 const broken=analyzeSource('a.ts','const = ;\nconst NEXT_PUBLIC_SECRET="value";','https://github.com/a/b');assert.equal(broken.checks.find(c=>c.rule==='repo.public-secret')?.status,'fail');assert.equal(broken.findings.find(f=>f.rule==='repo.public-secret')?.line,2);
 const clean=analyzeSource('a.ts','const = ;\n// NEXT_PUBLIC_SECRET="value"\nconst label="NEXT_PUBLIC_SECRET=value";','https://github.com/a/b');assert.equal(clean.checks.find(c=>c.rule==='repo.public-secret')?.status,'pass');
 const lexError=analyzeSource('a.ts','const x="unterminated','https://github.com/a/b');assert.equal(lexError.checks.find(c=>c.rule==='repo.public-secret')?.status,'unavailable');
});
test('syntax diagnostics expose numeric codes and locations without leaking source text',()=>{
 const result=analyzeJavaScript('a.ts','const = ;');assert.ok(result.errors.length);assert.ok(result.errors.every(e=>Number.isInteger(e.code)&&e.line>=1&&e.column>=1));
});
test('valid JSX text with apostrophes does not disable public-secret checks',async()=>{
 const {analyzeSource}=await import('../src/lib/repository/analyzer');const r=analyzeSource('x.tsx',"export const View=()=> <div>Don't stop</div>;",'https://github.com/a/b');assert.equal(r.checks.find(c=>c.rule==='repo.public-secret')?.status,'pass');
});
test('recovered typed/property assignments and positive mixed chunks are never converted to passes',async()=>{
 const {analyzeSource}=await import('../src/lib/repository/analyzer');
 for(const [file,body]of [['a.ts','const = ;\nconst NEXT_PUBLIC_SECRET: string="value";'],['a.ts','const = ;\nconst obj={NEXT_PUBLIC_SECRET: secret};'],['a.vue','<script lang="ts">const NEXT_PUBLIC_SECRET: string="value";</script>\n<script>const = ;</script>']])assert.equal(analyzeSource(file,body,'https://github.com/a/b').checks.find(c=>c.rule==='repo.public-secret')?.status,'fail');
});
test('regex text inside a malformed file cannot become a public-secret finding',async()=>{
 const {analyzeSource}=await import('../src/lib/repository/analyzer');const r=analyzeSource('a.ts','const = ;\nconst pattern=/NEXT_PUBLIC_SECRET=value/;','https://github.com/a/b');assert.ok(!r.findings.some(f=>f.rule==='repo.public-secret'));assert.notEqual(r.checks.find(c=>c.rule==='repo.public-secret')?.status,'pass');
});
