import {test} from 'node:test';
import assert from 'node:assert/strict';
import {evaluateChecks,secretCount} from '../src/lib/checks';
import {analyze} from '../src/lib/audit';
import {redact} from '../src/lib/redaction';
const page=(headers:Record<string,string>={},body='<html><body></body></html>')=>({url:'https://example.com/',status:200,headers:{'content-type':'text/html',...headers},body,elapsedMs:100,bytes:body.length});
const check=(rule:string,headers:Record<string,string>={},body?:string)=>evaluateChecks(page(headers,body)).find(c=>c.rule===rule)!;
test('security evaluates policy values rather than header presence',()=>{
 assert.equal(check('security.hsts',{'strict-transport-security':'max-age=0'}).status,'fail');
 assert.equal(check('security.frame',{'x-frame-options':'ALLOWALL'}).status,'fail');
 assert.equal(check('security.csp',{'content-security-policy':"default-src *; script-src 'unsafe-inline' *"}).status,'fail');
 assert.equal(check('security.csp',{'content-security-policy':"script-src 'nonce-abc123' 'unsafe-inline' 'strict-dynamic'; object-src 'none'"}).status,'pass');
 assert.equal(check('security.csp',{'content-security-policy-report-only':"default-src 'none'"}).status,'fail');
});
test('cookies inspect session attributes without storing cookie values',()=>{
 const c=check('security.cookies',{'set-cookie':'session=VERY_PRIVATE_VALUE; Path=/; SameSite=None\nprefs=light; Secure'});
 assert.equal(c.status,'fail');assert.ok(!JSON.stringify(c).includes('VERY_PRIVATE_VALUE'));
 assert.equal(check('security.cookies',{'set-cookie':'session=secret; Secure; HttpOnly; SameSite=Lax'}).status,'pass');
 assert.equal(check('security.cookies').status,'not_applicable');
});
test('credentialed wildcard CORS is invalid configuration, not proven data leakage',()=>{
 const c=check('security.cors',{'access-control-allow-origin':'*','access-control-allow-credentials':'true'});
 assert.equal(c.status,'fail');assert.match(c.evidence,/المتصفح/);
 assert.equal(check('security.cors',{'access-control-allow-origin':'*'}).status,'pass');
});
test('password GET forms and active mixed content are reported with actionable detail',()=>{
 const result=analyze(page({},'<form method="GET"><input name="password" type="password"></form><script src="http://example.com/a.js"></script>'));
 assert.equal(result.checks.find(c=>c.rule==='security.password-form')?.status,'fail');
 const f=result.findings.find(f=>f.rule==='security.password-form')!;
 assert.ok(f.security?.impact);assert.ok(f.security?.fixSteps.length);assert.ok(f.checks.length);
 assert.equal(result.checks.find(c=>c.rule==='security.active-mixed')?.status,'fail');
});
test('public keys are not secrets; private keys and provider tokens are masked',()=>{
 assert.equal(secretCount('AKIA1234567890123456 sb_publishable_abcdefghijk'),0);
 const values=['-----BEGIN PRIVATE KEY-----\nYWJjZGVm\n-----END PRIVATE KEY-----','github_pat_abcdefghijklmnopqrstuvwxyz1234567890','postgresql://user:secretpass@db.example.com/db'];
 for(const value of values){assert.ok(secretCount(value)>0);assert.ok(!redact(value).includes(value));}
});
test('document rules unavailable on a failed HTML response',()=>{
 const checks=evaluateChecks({...page(),status:404});
 assert.equal(checks.find(c=>c.rule==='security.password-form')?.status,'unavailable');
});
test('multiple CSP policies do not become a false positive; nonce policy does not hide unsafe-eval',()=>{
 assert.equal(check('security.csp',{'content-security-policy':"script-src *, script-src 'none'"}).status,'unavailable');
 assert.equal(check('security.csp',{'content-security-policy':"script-src 'nonce-abc' 'unsafe-eval'"}).status,'fail');
});
test('cookie expiration and combined Expires headers avoid reporting deleted sessions',()=>{
 assert.equal(check('security.cookies',{'set-cookie':'session=gone; Max-Age=0'}).status,'pass');
 assert.equal(check('security.cookies',{'set-cookie':'session=secret; Expires=Wed, 21 Oct 2099 07:28:00 GMT; Secure; HttpOnly, other=x; Secure'}).status,'pass');
});
test('CSP precedence, wildcard hosts and inline handlers do not earn false passing scores',()=>{
 assert.equal(check('security.frame',{'content-security-policy':'frame-ancestors *','x-frame-options':'DENY'}).status,'fail');
 assert.equal(check('security.csp',{'content-security-policy':'script-src https://*'}).status,'fail');
 assert.equal(check('security.csp',{'content-security-policy':"script-src 'unsafe-inline'; script-src-elem 'nonce-YWJj'; script-src-attr 'unsafe-inline'"}).status,'fail');
 assert.equal(check('security.frame',{'content-security-policy':"frame-ancestors 'self'",'x-frame-options':'ALLOWALL'}).status,'pass');
});
test('security detail survives report and prompt export without secret values',async()=>{
 const {markdownReport,scanRemediationPrompt}=await import('../src/lib/prompts');
 const output=analyze(page({'set-cookie':'session=never-export-this; SameSite=None'}));
 const scan={id:'security-fixture',project_id:'p',owner_id:'u',status:'completed' as const,stage:'done',created_at:0,updated_at:0,lease_until:0,is_demo:1,error:null,result:{...output,pages:[{url:'https://example.com/',status:200,elapsedMs:1,bytes:1}],scope:'https://example.com/',engine:'fixture',errors:[]}};
 for(const text of [markdownReport(scan),scanRemediationPrompt(scan)]){assert.match(text,/Set-Cookie/);assert.match(text,/طريقة الفحص/);assert.ok(!text.includes('never-export-this'));}
});
test('element-only CSP cannot claim protection for handlers and eval',()=>{
 assert.equal(check('security.csp',{'content-security-policy':"script-src-elem 'nonce-YWJj'"}).status,'fail');
});
