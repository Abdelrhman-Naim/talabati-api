import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateChecks} from '../src/lib/checks.ts';
import {summarizeChecks} from '../src/lib/scoring.ts';
import type {HttpPage} from '../src/lib/types.ts';
import type {BrowserObservation} from '../src/lib/types.ts';
const page=(body:string,status=200):HttpPage=>({url:'https://example.com/',status,headers:{'content-type':'text/html'},body,bytes:1000,elapsedMs:120});
test('checks capture passes as well as failures across all requested categories',()=>{
 const checks=evaluateChecks(page('<html lang="ar"><head><title>عنوان</title></head><body><h1>مرحبا</h1></body></html>'));
 assert.equal(checks.find(c=>c.rule==='seo.title')?.status,'pass');assert.equal(checks.find(c=>c.rule==='seo.description')?.status,'fail');
 for(const id of ['seo','geo','security','accessibility','performance','technical','ux'])assert.ok(checks.some(c=>c.category===id));
 assert.equal(checks.find(c=>c.rule==='performance.lcp')?.status,'unavailable');
 assert.equal(checks.find(c=>c.rule==='a11y.image-alt')?.status,'not_applicable');
});
test('valid structured content improves measured GEO readiness compared with empty HTML',()=>{
 const rich='<!doctype html><html lang="ar"><head><title>دليل</title><meta name="author" content="Author"><script type="application/ld+json">{"@context":"https://schema.org","@type":"Article","author":{"name":"A"},"dateModified":"2026-11-06"}</script></head><body><h1>دليل واضح</h1><h2>شرح الموضوع</h2><p>'+('محتوى مفيد. '.repeat(100))+'</p></body></html>';
 const a=summarizeChecks(evaluateChecks(page(rich))).categories.find(c=>c.id==='geo')!;const b=summarizeChecks(evaluateChecks(page('<html><body></body></html>'))).categories.find(c=>c.id==='geo')!;
 assert.ok(a.score!>b.score!);assert.equal(a.score,100);
});
test('malformed JSON-LD fails validation without persisting raw secret content',()=>{
 const checks=evaluateChecks(page('<script type="application/ld+json">{"token":"sb_secret_abcdefghijklmnop", broken}</script>'));
 assert.equal(checks.find(c=>c.rule==='geo.structured-valid')?.status,'fail');assert.ok(!JSON.stringify(checks).includes('sb_secret_abcdefghijklmnop'));
});
test('HTTP errors mark document checks unavailable rather than infer SEO success from an error document',()=>{
 const checks=evaluateChecks(page('<html><title>404 not found</title></html>',404));
 assert.equal(checks.find(c=>c.rule==='technical.http')?.status,'fail');assert.equal(checks.find(c=>c.rule==='seo.title')?.status,'unavailable');
 assert.equal(summarizeChecks(checks).categories.find(c=>c.id==='seo')?.score,null);
 assert.equal(summarizeChecks(checks).categories.find(c=>c.id==='performance')?.score,null);
});
test('a dangling aria-labelledby reference does not count as a named button',()=>{
 const checks=evaluateChecks(page('<button aria-labelledby="missing"></button>'));
 assert.equal(checks.find(c=>c.rule==='a11y.button-name')?.status,'fail');
});
test('adding malformed JSON-LD cannot improve GEO readiness',()=>{
 const baseline=summarizeChecks(evaluateChecks(page('<h1>Title</h1>'))).categories.find(c=>c.id==='geo')!.score!;
 const malformed=summarizeChecks(evaluateChecks(page('<h1>Title</h1><script type="application/ld+json">{broken}</script>'))).categories.find(c=>c.id==='geo')!.score!;
 assert.ok(malformed<=baseline);
});
test('an empty schema author object is not an identified author',()=>{
 const checks=evaluateChecks(page('<script type="application/ld+json">{"@type":"Article","author":{}}</script>'));
 assert.equal(checks.find(c=>c.rule==='geo.author')?.status,'fail');
});
test('rendered browser observations unlock actual measured checks and preserve unavailable field INP',()=>{
 const observed:BrowserObservation={mode:'browser',viewport:'1365×900 desktop',observedMs:5000,lcp:1600,cls:0.04,domReady:500,overflow:false,consoleErrors:[],requests:[],checks:[{id:'axe.test',rule:'axe.color-contrast',category:'accessibility',status:'fail',weight:2,title:'Contrast',url:'https://example.com/',evidence:'button',recommendation:'fix colors'}],services:[],warnings:[],scriptAttempts:1,scriptSuccesses:1};
 const checks=evaluateChecks({...page('<h1>Rendered</h1>'),browser:observed});
 for(const rule of ['seo.rendered','performance.lcp','performance.cls','technical.console','ux.visual'])assert.equal(checks.find(c=>c.rule===rule)?.status,'pass');
 assert.equal(checks.find(c=>c.rule==='a11y.contrast')?.status,'fail');assert.equal(checks.find(c=>c.rule==='performance.inp')?.status,'unavailable');
});
test('removing an inline script from rendered DOM cannot hide a secret exposed in original HTML',()=>{
 const checks=evaluateChecks({...page('<h1>Rendered</h1>'),sourceBody:'<script>const key="sb_secret_abcdefghijklmnopqrstuvwxyz";document.currentScript.remove()</script>'});
 assert.equal(checks.find(c=>c.rule==='security.secret')?.status,'fail');assert.ok(!JSON.stringify(checks).includes('sb_secret_abcdefghijklmnopqrstuvwxyz'));
});
