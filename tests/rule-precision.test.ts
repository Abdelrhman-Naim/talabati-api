import {test} from 'node:test';import assert from 'node:assert/strict';import {analyzeSource} from '../src/lib/repository/analyzer';
const findings=(code:string,rule:string,file='module.tsx')=>analyzeSource(file,code,'https://github.com/fixture/repo/blob/'+'a'.repeat(40)+'/'+file).findings.filter(f=>f.rule===rule);
test('weak hash: security inputs, security outputs, HMAC and secret comparisons are medium',()=>{for(const code of [
 `import {createHash} from 'node:crypto'; function hashPassword(password:string){return createHash('md5').update(password).digest('hex')}`,
 `import {createHash} from 'crypto'; const sessionToken=createHash('sha1').update(input).digest('hex');`,
 `import {createHmac} from 'node:crypto'; const signature=createHmac('sha1',key).update(message).digest('hex');`,
 `const digest=createHash('md5').update(value).digest('hex'); if(digest===expectedSecret) grant();`,
 `const h=createHash('md5'); h.update(credentials.password); const digest=h.digest('hex');`
]){const f=findings(code,'repo.weak-hash');assert.equal(f.length,1,code);assert.equal(f[0].severity,'medium');}});
test('weak hash: checksums, cache keys and ETags are not medium findings',()=>{for(const code of [
 `import {createHash} from 'crypto'; export const checksum=(text:string)=>createHash('md5').update(text).digest('hex');`,
 `const cacheKey=createHash('sha1').update(JSON.stringify(data)).digest('hex');`,
 `function entityTag(body:string){const etag=createHash('md5').update(body).digest('hex'); return etag;}`,
 `const password='unrelated'; const checksum=createHash('sha1').update(content).digest('hex');`,
 `// password token auth\n const checksum=createHash('md5').update(content).digest('hex');`
])assert.equal(findings(code,'repo.weak-hash').filter(f=>f.severity!=='info').length,0,code);});
test('HTML: dynamic JSX, assignment, element access and insertAdjacentHTML remain reported',()=>{for(const code of [
 `function Page({html}:{html:string}){return <div dangerouslySetInnerHTML={{__html:html}}/>}`,
 `node.innerHTML=input;`, `node['outerHTML']=input;`,`node.insertAdjacentHTML('beforeend',input);`,
 `const template='<p>trusted</p>'; function Page(template:string){return <div dangerouslySetInnerHTML={{__html:template}}/>}`,
 `let markup='<b>safe</b>'; markup=input; node.innerHTML=markup;`,
 `const props={__html:'safe'}; props.__html=input; const x=<div dangerouslySetInnerHTML={props}/>;`
])assert.equal(findings(code,'repo.html-sink').length,1,code);});
test('HTML: literal and compile-time const string expressions are not reported',()=>{for(const code of [
 `const x=<div dangerouslySetInnerHTML={{__html:'<p>static</p>'}}/>;`,
 `const trusted='<p>source-authored</p>'; const x=<div dangerouslySetInnerHTML={{__html:trusted}}/>;`,
 `const title='Hello'; node.innerHTML='<h1>'+title+'</h1>';`,
 'const title="Hello"; node.insertAdjacentHTML("beforeend",`<h1>${title}</h1>`);',
 `const props={__html:'source-authored'}; const x=<div dangerouslySetInnerHTML={props}/>;`
])assert.equal(findings(code,'repo.html-sink').length,0,code);});
test('HTML: proven DOMPurify and sanitize-html bindings suppress sanitized values',()=>{for(const code of [
 `import DOMPurify from 'dompurify'; node.innerHTML=DOMPurify.sanitize(input);`,
 `import {sanitize as clean} from 'dompurify'; const safe=clean(input); const x=<div dangerouslySetInnerHTML={{__html:safe}}/>;`,
 `import sanitizeHtml from 'sanitize-html'; node.insertAdjacentHTML('beforeend',sanitizeHtml(input));`,
 `const DOMPurify=require('dompurify'); node.innerHTML=DOMPurify.sanitize(input);`
])assert.equal(findings(code,'repo.html-sink').length,0,code);});
test('HTML: sanitizer lookalikes, shadowed bindings and unsafe concatenation still report',()=>{for(const code of [
 `const DOMPurify={sanitize:(x:string)=>x}; node.innerHTML=DOMPurify.sanitize(input);`,
 `import DOMPurify from 'dompurify'; function render(DOMPurify:any){node.innerHTML=DOMPurify.sanitize(input);}`,
 `import DOMPurify from 'dompurify'; node.innerHTML=DOMPurify.sanitize(input)+untrusted;`,
 `import DOMPurify from 'dompurify'; DOMPurify.sanitize=(x)=>x; node.innerHTML=DOMPurify.sanitize(input);`
])assert.equal(findings(code,'repo.html-sink').length,1,code);});
test('unsupported non-JS HTML context is unavailable rather than a false constant-sink finding',()=>{const r=analyzeSource('template.php',`<?php $x=1; ?> element.innerHTML = 'static';`,'https://example.com/template.php');assert.equal(r.findings.filter(f=>f.rule==='repo.html-sink').length,0);assert.equal(r.checks.find(c=>c.rule==='repo.html-sink')?.status,'unavailable');});
test('hash context follows local security input aliases without borrowing unrelated cache/log arguments',()=>{assert.equal(findings(`const value=request.body.password; const digest=createHash('md5').update(value).digest('hex');`,'repo.weak-hash').length,1);for(const code of [`const digest=createHash('md5').update(content).digest('hex'); console.log(digest,password);`,`const cacheKey=createHash('sha1').update(content).digest('hex'); cache.set(cacheKey,sessionToken);`])assert.equal(findings(code,'repo.weak-hash').length,0,code);});
