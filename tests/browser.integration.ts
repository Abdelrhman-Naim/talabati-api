import test from 'node:test';
import assert from 'node:assert/strict';
import {createBrowserCollector} from '../src/lib/browser.ts';
import {analyze} from '../src/lib/audit.ts';
import type {HttpPage} from '../src/lib/types.ts';

test('real Chromium renders SPA scripts and API data, runs axe, and blocks writing/private resources',{timeout:60000},async()=>{
 const calls:string[]=[];
 const transport=async(url:string):Promise<HttpPage>=>{
  calls.push(url);const u=new URL(url);let body='',type='text/html';
  if(u.pathname==='/')body='<!doctype html><html lang="en"><head><title>Loading</title></head><body><main id="root"></main><script src="/app.js?v=1"></script></body></html>';
  else if(u.pathname==='/app.js'){type='application/javascript';body=`document.title='Rendered Academy';document.getElementById('root').innerHTML='<h1>Real rendered heading</h1><img alt="" src="/missing.png"><button></button>';fetch('https://api.example.net/courses').then(r=>r.json()).then(d=>document.getElementById('root').insertAdjacentHTML('beforeend','<p>'+d.title+'</p>'));fetch('/mutate',{method:'POST',body:'no'}).catch(()=>{});fetch('http://127.0.0.1/private').catch(()=>{});`;}
  else if(u.hostname==='api.example.net'){type='application/json';body='{"title":"Course from API"}';}
  return {url,status:200,headers:{'content-type':type,'access-control-allow-origin':'https://app.example'},body,rawBody:Buffer.from(body),bytes:Buffer.byteLength(body),elapsedMs:10};
 };
 const collector=await createBrowserCollector({transport,executablePath:process.env.TEST_CHROMIUM_PATH??'/usr/bin/chromium'});
 try{
  const page=await collector.collect('https://app.example/','https://app.example');
  assert.ok(page.body.includes('Real rendered heading'));assert.ok(page.body.includes('Course from API'));
  assert.ok(!calls.some(u=>u.includes('127.0.0.1')||u.endsWith('/mutate')));
  assert.ok(page.browser?.requests.some(r=>r.method==='POST'&&r.blocked));
  assert.ok(page.browser?.checks.some(c=>c.rule.startsWith('axe.')&&c.status==='fail'));
  const output=analyze(page);assert.equal(output.checks.find(c=>c.rule==='seo.rendered')?.status,'pass');
  assert.ok(output.services.some(s=>s.origin==='https://api.example.net'&&s.status==='observed_request'));
  assert.ok(page.browser?.domReady!==null);
 }finally{await collector.close();}
});
