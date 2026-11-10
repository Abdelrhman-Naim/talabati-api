import test from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../src/lib/audit.ts';
import type {HttpPage} from '../src/lib/types.ts';
const page=(body:string):HttpPage=>({url:'https://academy.example/',status:200,headers:{'content-type':'text/html'},body,elapsedMs:40,bytes:body.length});
test('finds missing title and image names with precise evidence, not invented code locations',()=>{
  const output=analyze(page('<html><body><h1>Courses</h1><img src="x.png"><input id="email"></body></html>'));
  assert.ok(output.findings.some(f=>f.rule==='seo.title'));
  assert.ok(output.findings.some(f=>f.rule==='a11y.image-alt'));
  assert.ok(output.findings.every(f=>!f.file));
  assert.ok(output.checks.some(c=>c.rule==='performance.lcp'&&c.status==='unavailable'));
  assert.ok(output.checks.some(c=>c.rule==='seo.h1'&&c.status==='pass'));
  assert.equal(output.coverage.find(c=>c.id==='geo')?.status,'partial');
});
test('discovers an external Supabase reference without claiming to have probed it',()=>{
  const output=analyze(page('<script>const api="https://abc.supabase.co/rest/v1/courses"; const key="sb_publishable_abcdefghijklmno";</script>'));
  assert.equal(output.services[0].origin,'https://abc.supabase.co');
  assert.equal(output.services[0].status,'observed_reference');
  assert.ok(!output.findings.some(f=>f.rule==='security.secret'));
});
test('flags privileged secret but never returns the raw value',()=>{
  const raw='sb_secret_abcdefghijklmnopqrstuvwxyz012345';
  const output=analyze(page(`<script>const admin="${raw}";</script>`));
  assert.ok(output.findings.some(f=>f.rule==='security.secret'));
  assert.ok(!JSON.stringify(output).includes(raw));
});
test('good explicit page metadata does not generate missing-title or missing-alt findings',()=>{
  const output=analyze(page('<html lang="ar"><head><title>عنوان الموقع</title><meta name="description" content="وصف"><meta name="viewport" content="width=device-width"><link rel="canonical" href="https://academy.example/"></head><body><h1>عنوان</h1><img src="x.png" alt=""><label for="email">بريد</label><input id="email"></body></html>'));
  assert.ok(!output.findings.some(f=>['seo.title','a11y.image-alt','a11y.input-name'].includes(f.rule)));
});
test('identifies secret service-role JWTs but accepts public anon JWT references',()=>{
  const token=(role:string)=>`eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({role})).toString('base64url')}.testsignature123456789`;
  assert.ok(analyze(page(`<script>${token('service_role')}</script>`)).findings.some(f=>f.rule==='security.secret'));
  assert.ok(!analyze(page(`<script>${token('anon')}</script>`)).findings.some(f=>f.rule==='security.secret'));
});
