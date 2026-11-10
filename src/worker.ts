import {failedWorkerResult} from './lib/findings-adapter';
import {randomUUID} from 'node:crypto';
import {getStore} from './lib/db';
import {runRepositoryJob} from './lib/repository/job';
import {runJob} from './lib/jobs';
import {SCORE_VERSION} from './lib/scoring';
import {collect,redact} from './lib/network';
import {createBrowserCollector} from './lib/browser';
import {browserSelfcheck} from './lib/browser-selfcheck';
import {setTimeout} from 'node:timers/promises';
const store=getStore(),holder=randomUUID();
if(!store.acquireLock('scan-worker',holder,Date.now()+30000)){console.log('A current worker is already active; keeping it.');store.close();process.exit(0);}
let stopping=false,jobId:string|null=null,mode:'http'|'browser'='http',detail='جارٍ اختبار جاهزية المتصفح';
let renderer:Awaited<ReturnType<typeof createBrowserCollector>>|null=null;
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{stopping=true;void renderer?.close().catch(()=>{});});
const timer=globalThis.setInterval(()=>{if(!store.renewLock('scan-worker',holder,Date.now()+30000)){stopping=true;void renderer?.close().catch(()=>{});return;}store.heartbeat(mode,detail);if(jobId)store.renewJobLease(jobId);},4000);
try{
 if(process.env.SCAN_BROWSER!=='false'){
  try{renderer=await createBrowserCollector();const probe=await browserSelfcheck(renderer);mode='browser';detail=`Chromium + JavaScript + axe ready (${probe.axeChecks} self-check rules).`;
  }catch(e){await renderer?.close().catch(()=>{});renderer=null;const message=e instanceof Error?e.message:'unknown';const reason=message.includes('socket() failed')?'بيئة التشغيل تمنع إنشاء socket لتشغيل Chromium':redact(message.split('\n')[0]).slice(0,200);detail='HTTP متاح؛ Chromium: '+reason+'. ثبّت المتصفح أو راجع صلاحيات السيرفر وأعد التشغيل.';}
 }else detail='نمط HTTP محدد بإعداد SCAN_BROWSER=false.';
 store.heartbeat(mode,detail);console.log(`Aegis worker 0.12.0 ready: ${mode}. ${detail}`);
 while(!stopping){
  const job=store.claimJob();
  if(!job){await setTimeout(1500);continue;}jobId=job.id;
  try{
   if(job.kind==='repository')await runRepositoryJob(store,job);
   else await runJob(store,job,async(url,origin,signal,progress,allowed)=>{
    if(renderer){const activeRenderer=renderer;const abort=()=>{void activeRenderer.close().catch(()=>{});};signal?.addEventListener('abort',abort,{once:true});try{return await activeRenderer.collect(url,origin,undefined,progress,allowed);}catch(e){if(signal?.aborted)throw new Error('انتهت مهلة جمع الصفحة؛ أوقف المتصفح.');void renderer.close().catch(()=>{});renderer=null;mode='http';detail='توقف المتصفح أثناء الجمع: '+redact(e instanceof Error?e.message:'خطأ غير معروف').slice(0,180);store.heartbeat(mode,detail);const page=await collect(url,origin,0,{signal,allowUrl:allowed});page.collectorWarning=detail+'؛ تم تحليل HTML المصدر.';return page;}finally{signal?.removeEventListener('abort',abort);if(signal?.aborted){renderer=null;mode='http';detail='أوقف المتصفح لتجاوز مهلة الصفحة؛ اكتملت النتائج المتاحة فقط.';store.heartbeat(mode,detail);}}}
    const page=await collect(url,origin,0,{signal,allowUrl:allowed});page.collectorWarning=detail;return page;
   },250,{fetchDiscovery:(url,origin,signal,_progress,allowed)=>collect(url,origin,0,{signal,allowUrl:allowed})});
  }catch{store.finishScan(job.id,'failed',failedWorkerResult(SCORE_VERSION),'تعذر إكمال التحليل');}
  finally{jobId=null;}
 }
}finally{clearInterval(timer);await renderer?.close().catch(()=>{});store.releaseLock('scan-worker',holder);store.close();}
