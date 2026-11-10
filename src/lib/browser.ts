import {discoverApiReferences,mergeApiServices} from './api-discovery';
import {chromium,type Browser} from 'playwright';
import axe from 'axe-core';
import {withDeadline} from './deadline';
import {existsSync} from 'node:fs';
import {requestResource,redact,validateTarget} from './network';
import {resourcePolicy} from './resource-policy';
import {securityChecks} from './security';
import type {AuditCheck,BrowserObservation,HttpPage,NetworkObservation,Service} from './types';

type Transport=(url:string,options?:{method?:'GET'|'HEAD';headers?:Record<string,string>;signal?:AbortSignal})=>Promise<HttpPage>;
export function browserExecutable(){
 if(process.env.CHROMIUM_EXECUTABLE_PATH&&existsSync(process.env.CHROMIUM_EXECUTABLE_PATH))return process.env.CHROMIUM_EXECUTABLE_PATH;
 const packaged=chromium.executablePath();if(existsSync(packaged))return packaged;
 for(const path of ['/usr/bin/chromium','/usr/bin/chromium-browser','/usr/bin/google-chrome'])if(existsSync(path))return path;
 return null;
}
const initMetrics=`(() => {
 const m={lcp:null,cls:0,session:0,start:0,last:0,clsObserved:false};
 Object.defineProperty(window,'__aegisMetrics',{value:m});
 try { new PerformanceObserver(list=>{for(const e of list.getEntries())m.lcp=e.startTime}).observe({type:'largest-contentful-paint',buffered:true}); }catch{}
 try { m.clsObserved=PerformanceObserver.supportedEntryTypes.includes('layout-shift');new PerformanceObserver(list=>{for(const e of list.getEntries()){if(e.hadRecentInput)continue;if(m.last&&e.startTime-m.last<1000&&e.startTime-m.start<5000)m.session+=e.value;else{m.session=e.value;m.start=e.startTime;}m.last=e.startTime;m.cls=Math.max(m.cls,m.session);}}).observe({type:'layout-shift',buffered:true}); }catch{}
})();`;

export async function createBrowserCollector(options:{transport?:Transport;executablePath?:string}={}){
 const executablePath=options.executablePath??browserExecutable();if(!executablePath)throw new Error('Chromium غير مثبت؛ نفذ npm run browser:install');
 const transport=options.transport??requestResource;
 const browser:Browser=await chromium.launch({executablePath,headless:true,proxy:{server:'http://127.0.0.1:9'},args:['--proxy-bypass-list=<-loopback>','--force-webrtc-ip-handling-policy=disable_non_proxied_udp','--disable-quic','--disable-background-networking','--dns-prefetch-disable']});
 async function collectPage(input:string,origin=new URL(input).origin,fixtureTransport?:Transport,progress?:(message:string)=>void,allowed?:(url:string)=>boolean):Promise<HttpPage>{
   const fetchResource=fixtureTransport??transport;const resourcesAbort=new AbortController();
   const target=validateTarget(input);if(target.origin!==origin)throw new Error('رابط خارج النطاق المخول');
   const context=await browser.newContext({viewport:{width:1365,height:900},deviceScaleFactor:1,serviceWorkers:'block',acceptDownloads:false});
   const observations:NetworkObservation[]=[],checks:AuditCheck[]=[],services:Service[]=[],warnings:string[]=[],consoleErrors:string[]=[];
   const apiDiscovery={files:0,origins:0,excluded:0,limited:false};const started=Date.now();let requests=0,totalBytes=0,scriptAttempts=0,scriptSuccesses=0;
   let document:HttpPage|undefined;
   const service=(url:string,kind:string,blocked:boolean)=>{try{const u=new URL(url);if(!['fetch','xhr'].includes(kind)&&u.origin===origin)return;if(!['fetch','xhr','script'].includes(kind)&&!u.hostname.endsWith('.supabase.co'))return;const existing=services.find(s=>s.origin===u.origin);if(existing){if(existing.status==='blocked_request'&&!blocked)existing.status='observed_request';if(existing.paths.length<8&&!existing.paths.includes(u.pathname))existing.paths.push(redact(u.pathname));return;}services.push({origin:u.origin,type:u.hostname.endsWith('.supabase.co')?'Supabase':['fetch','xhr'].includes(kind)?'API مرصود':'مصدر JavaScript خارجي',source:redact(input),status:blocked?'blocked_request':'observed_request',paths:[redact(u.pathname)]});}catch{}};
   await context.routeWebSocket('**/*',socket=>socket.close());
   await context.addInitScript({content:initMetrics});
   await context.route('**/*',async route=>{
    const req=route.request(),url=req.url(),method=req.method(),kind=req.resourceType();
    const observation:NetworkObservation={url:redact(url),method,resourceType:kind,status:null,blocked:false};
    if(observations.length<150)observations.push(observation);if(kind==='script')scriptAttempts++;
    try{
     if(++requests>100||totalBytes>15*1024*1024||Date.now()-started>40000)throw new Error('انتهت ميزانية موارد المتصفح');
     if(req.isNavigationRequest()&&allowed&&!allowed(url))throw new Error('الوجهة مستبعدة حسب سياسة الزحف');
     const headers=resourcePolicy(url,method,req.headers(),req.isNavigationRequest(),origin);
     const response=await fetchResource(url,{method:method as 'GET'|'HEAD',headers,signal:resourcesAbort.signal});observation.status=response.status;totalBytes+=response.bytes;if(response.status>=400&&warnings.length<25)warnings.push(`HTTP ${response.status}: ${redact(url)}`);
     if(req.isNavigationRequest()&&req.frame()===context.pages()[0]?.mainFrame())document=response;
     service(url,kind,false);
     if(kind==='script'){
      const usable=response.status>=200&&response.status<300&&/(?:javascript|ecmascript|text\/plain)/i.test(response.headers['content-type']??'');
      if(usable){scriptSuccesses++;const found=discoverApiReferences('collected.js',response.body,response.url,input);apiDiscovery.files++;apiDiscovery.excluded+=found.excluded;const merged=mergeApiServices(services,found.services);apiDiscovery.limited=apiDiscovery.limited||found.limited||merged;apiDiscovery.origins=services.filter(s=>/API|Supabase/i.test(s.type)).length;checks.push(...found.checks);}
      const secret=securityChecks(response).find(c=>c.rule==='security.secret')!;if(!usable)secret.status='unavailable';checks.push(secret);
     }
     if(kind==='fetch'||kind==='xhr')checks.push(...securityChecks(response).filter(c=>['security.cors','security.cookies'].includes(c.rule)));
     const responseHeaders={...response.headers};delete responseHeaders['transfer-encoding'];delete responseHeaders['connection'];delete responseHeaders['content-encoding'];delete responseHeaders['content-length'];
     await route.fulfill({status:response.status,headers:responseHeaders,body:Buffer.from(response.rawBody??response.body)});
    }catch(e){
     observation.blocked=true;observation.reason=redact(e instanceof Error?e.message:'تعذر جلب المورد').slice(0,180);service(url,kind,true);
     if(warnings.length<25)warnings.push(`${kind}: ${observation.reason}`);
     if(kind==='script')checks.push({id:'security.secret|'+redact(url),rule:'security.secret',category:'security',status:'unavailable',weight:4,title:'فحص مصدر JavaScript',url:redact(url),evidence:'المصدر محظور أو تعذر جلبه؛ لم يعتبر نجاحًا.',recommendation:'راجع المصدر وسبب فشل الجمع.'});
     await route.abort('blockedbyclient').catch(()=>{});
    }
   });
   const page=await context.newPage();page.setDefaultTimeout(15000);
   page.on('pageerror',e=>{if(consoleErrors.length<12)consoleErrors.push(redact(e.message).slice(0,300));});
   page.on('popup',popup=>{void popup.close();});
   try{
    progress?.('فتح الصفحة وتشغيل JavaScript ضمن سياسة الموارد العامة');
    await page.goto(target.href,{waitUntil:'domcontentloaded',timeout:45000});
    progress?.('انتظار بيانات الصفحة وطلبات API ضمن نافذة الانتظار المحدودة');
    await page.waitForLoadState('networkidle',{timeout:7000}).catch(()=>warnings.push('لم تصل الشبكة إلى الاستقرار خلال نافذة الانتظار؛ النتيجة عينة زمنية محدودة.'));
    const final=validateTarget(page.url());if(final.origin!==origin)throw new Error('النطاق النهائي غير مخول');
    if(!document)throw new Error('لم يجمع مستند المتصفح الرئيسي');
    progress?.('استخراج DOM وقياسات LCP وCLS والتمدد الأفقي');
    const body=await page.content();if(Buffer.byteLength(body)>2*1024*1024)throw new Error('DOM المعروض تجاوز 2MB');
    const metrics=await page.evaluate(`(() => {const m=window.__aegisMetrics||{}, n=performance.getEntriesByType('navigation')[0];return {lcp:typeof m.lcp==='number'?m.lcp:null,cls:m.clsObserved?m.cls:null,domReady:n?n.domContentLoadedEventEnd:null,overflow:document.documentElement.scrollWidth>innerWidth+2};})()` ) as {lcp:number|null;cls:number|null;domReady:number|null;overflow:boolean};
    try{
     progress?.('تشغيل axe لفحوص الوصول على العناصر المعروضة');
     await page.evaluate(axe.source);
     const a=await page.evaluate(`(async()=>{const r=await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21a','wcag21aa']}});return {passes:r.passes.map(x=>({id:x.id,help:x.help,impact:x.impact,nodes:x.nodes.map(n=>n.target)})),violations:r.violations.map(x=>({id:x.id,help:x.help,impact:x.impact,nodes:x.nodes.map(n=>n.target)})),incomplete:r.incomplete.map(x=>({id:x.id,help:x.help,impact:x.impact,nodes:x.nodes.map(n=>n.target)}))};})()` ) as {passes:AxeItem[];violations:AxeItem[];incomplete:AxeItem[]};
     for(const [group,status] of [[a.passes,'pass'],[a.violations,'fail'],[a.incomplete,'unavailable']] as const)for(const item of group){checks.push({id:'axe.'+item.id+'|'+redact(final.href),rule:'axe.'+item.id,category:'accessibility',status,weight:item.impact==='critical'?4:item.impact==='serious'?3:1,title:'axe: '+redact(item.help),url:redact(final.href),evidence:status==='pass'?'اجتازت العناصر المقاسة قاعدة axe.':redact(JSON.stringify(item.nodes.slice(0,5))).slice(0,500),recommendation:'راجع العناصر المحددة والقاعدة ثم أعد اختبار الوصول.',severity:item.impact==='critical'||item.impact==='serious'?'medium':'low'});}
    }catch{warnings.push('تعذر إكمال axe؛ بقيت اختبارات الوصول الآلية غير متاحة.');}
    const observation:BrowserObservation={apiDiscovery,mode:'browser',viewport:'1365×900 desktop',observedMs:Date.now()-started,...metrics,consoleErrors,requests:observations,checks,services,warnings,scriptAttempts,scriptSuccesses};
    return {...document,url:final.href,sourceBody:document.body,body,browser:observation};
   }finally{resourcesAbort.abort();await withDeadline(context.close(),3000,()=>browser.close()).catch(()=>{});}
  }
 return {collect(input:string,origin=new URL(input).origin,fixtureTransport?:Transport,progress?:(message:string)=>void,allowed?:(url:string)=>boolean){return withDeadline(collectPage(input,origin,fixtureTransport,progress,allowed),45000,()=>browser.close());},async close(){await withDeadline(browser.close(),3000,()=>{}).catch(()=>{});}};
}
type AxeItem={id:string;help:string;impact:string|null;nodes:unknown[]};
