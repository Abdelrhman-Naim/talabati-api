import type {createBrowserCollector} from './browser';
import type {HttpPage} from './types';
export async function browserSelfcheck(collector:Awaited<ReturnType<typeof createBrowserCollector>>){
 const base='https://aegis-selfcheck.example';
 const page=await collector.collect(base+'/',base,async (url: string):Promise<HttpPage>=>{
  const script=new URL(url).pathname==='/app.js';
  const body=script?"document.querySelector('main').innerHTML='<h1>Engine ready</h1><button></button>';fetch('/blocked-write',{method:'POST'}).catch(()=>{});":'<!doctype html><html lang="en"><head><title>Engine check</title></head><body><main></main><script src="/app.js?v=1"></script></body></html>';
  return {url,status:200,headers:{'content-type':script?'application/javascript':'text/html'},body,rawBody:Buffer.from(body),bytes:Buffer.byteLength(body),elapsedMs:1};
 });
 if(!page.body.includes('Engine ready'))throw new Error('فشل الاختبار الذاتي: JavaScript لم يعرض DOM المتوقع');
 if(!page.browser?.checks.some(c=>c.rule.startsWith('axe.')))throw new Error('فشل الاختبار الذاتي: axe لم ينتج نتائج');
 if(!page.browser.requests.some(r=>r.method==='POST'&&r.blocked))throw new Error('فشل الاختبار الذاتي: حظر طلبات الكتابة غير مثبت');
 return {rendered:true,axeChecks:page.browser.checks.filter(c=>c.rule.startsWith('axe.')).length,writeBlocked:true};
}
