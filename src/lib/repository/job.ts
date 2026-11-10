import {normalizeLegacyResult} from '../findings-adapter';
import {runAutomaticApiHttp,identityCapability,type ApiHttpTransport} from '../auto-api-http';
import {mergeApiServices} from '../api-discovery';
import {runApiTests,type ApiTransport} from '../api-tests';
import {parseLockfile,isNpmLockfile,type InstalledPackage} from './dependencies';
import {auditDependencies,type OsvTransport,type DependencyAudit} from './osv';
import {dependencyResults} from './engine-results';
import {runRuntimeSecurity,type RuntimeCollector} from './runtime-security';
import type {Store} from '../db';
import type {Scan,ScanResult} from '../types';
import {SCORE_VERSION} from '../scoring';
import {redact} from '../redaction';
import {GitHubReader,UnsupportedRepositoryFile,type Snapshot,type RepositoryFile} from './github';
import {eligibleSource,analyzeSource} from './analyzer';
type Reader={snapshot:(branch:string,signal?:AbortSignal)=>Promise<Snapshot>;blob:(file:RepositoryFile,signal?:AbortSignal)=>Promise<string>};
export async function runRepositoryJob(store:Store,job:Scan,options:{reader?:Reader;maxFiles?:number;budgetMs?:number;requestMs?:number;pollMs?:number;osvTransport?:OsvTransport;runtimeCollect?:RuntimeCollector;apiTransport?:ApiTransport;apiHttpTransport?:ApiHttpTransport}={}){
 const repo=job.repository;if(job.kind!=='repository'||!repo)throw new Error('المهمة ليست فحص مستودع');
 const maxFiles=Math.min(3000,Math.max(1,options.maxFiles??(Number(process.env.REPOSITORY_MAX_FILES)||1000))),maxBytes=20*1024*1024,budget=options.budgetMs??600000,started=Date.now(),base=`https://github.com/${repo.owner}/${repo.name}`;
 const installed:InstalledPackage[]=[],lockErrors:string[]=[];let lockCount=0,lockIncomplete=false;
 const result:ScanResult={repository:{owner:repo.owner,name:repo.name,branch:repo.branch,commit:'',discovered:0,eligible:0,analyzed:0,excluded:0,failed:0,pending:0,bytes:0,truncated:false,maxFiles,maxBytes,files:[]},findings:[],services:[],coverage:[{id:'security',label:'أمان الكود',status:'partial',detail:'قواعد تحليل ثابت للمصادر المجموعة؛ دون تشغيل أو تحليل تدفق كامل أو اختبار API/RLS حي.'},{id:'technical',label:'إعدادات المشروع',status:'partial',detail:'قراءة إعدادات الحزم والمصادر؛ لا تثبيت أو بناء أو تشغيل.'},...(['seo','geo','performance','accessibility','ux'] as const).map(id=>({id,label:id,status:'not_run' as const,detail:'فحص المستودع لا يقيس الموقع المعروض أو تجربة المستخدم؛ استخدم فحص الرابط.'}))],pages:[],errors:[],scope:base,engine:'aegis-repository-security@0.12.0',capabilities:job.apiTests?[]:[identityCapability],apiDiscovery:{files:0,origins:0,excluded:0,limited:false},scoreVersion:SCORE_VERSION,checks:[],events:[]};
 let eventId=0;const running=()=>store.isRunning(job.id),stats=result.repository!;
 const event=(phase:'discovery'|'fetch'|'analyze'|'complete',status:'running'|'done'|'warning',message:string,url?:string)=>{if(!running())return;result.events!.push({id:String(++eventId),at:Date.now(),phase,status,message:redact(message),...(url?{url:redact(url)}:{})});if(result.events!.length>300)result.events!.splice(0,result.events!.length-300);store.progress(job.id,redact(message),normalizeLegacyResult(result));};
 async function read<T>(fn:(signal:AbortSignal)=>Promise<T>):Promise<T>{
  if(!running())throw new Error('أُلغي الفحص');const controller=new AbortController(),remaining=budget-(Date.now()-started);if(remaining<=0)throw new Error('انتهت ميزانية الوقت');let timer:ReturnType<typeof setTimeout>,monitor:ReturnType<typeof setInterval>;
  const interrupted=new Promise<never>((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new Error('انتهت مهلة قراءة GitHub'));},Math.max(1,Math.min(remaining,options.requestMs??45000)));monitor=setInterval(()=>{if(!running()){controller.abort();reject(new Error('أُلغي الفحص'));}},options.pollMs??200);});
  try{return await Promise.race([fn(controller.signal),interrupted]);}finally{clearTimeout(timer!);clearInterval(monitor!);controller.abort();}
 }
 const planned=job.apiTests?await runApiTests(store,{...job,apiTests:false}):{checks:[]};
 for(const c of planned.checks){c.execution!.state='planned';c.execution!.observed='بانتظار مرحلة اختبار API';if(job.apiTests){c.unavailableReason='collection_error';c.evidence='حالة مخططة لم تصل مرحلة التنفيذ بعد؛ لا نجاح محتسب.';}}
 result.checks!.push(...planned.checks);
 try{
  const token=store.repositoryCredential(job.owner_id,job.project_id,repo.id),reader=options.reader??new GitHubReader(repo,token);
  event('discovery','running','قراءة الفرع وتثبيت commit وقائمة ملفات GitHub',base);
  const snapshot=await read(signal=>reader.snapshot(repo.branch,signal));if(!running())return;
  stats.commit=snapshot.commit;stats.truncated=snapshot.truncated;stats.discovered=snapshot.files.length+snapshot.excluded;stats.excluded=snapshot.excluded;
  const candidates=snapshot.files.filter(f=>eligibleSource(f.path)).sort((a,b)=>Number(isNpmLockfile(b.path))-Number(isNpmLockfile(a.path)));stats.eligible=candidates.length;stats.pending=candidates.length;
  for(const f of snapshot.files)if(!eligibleSource(f.path)){stats.excluded++;if(stats.files.length<2000)stats.files.push({file:redact(f.path),url:base,status:'excluded',reason:'نوع ملف غير نصي أو مجلد اعتماديات/بناء مستبعد'});}
  result.scope=base+'/tree/'+snapshot.commit;
  if(snapshot.truncated)result.errors.push('GitHub أعاد شجرة ملفات مختصرة؛ لم يكتشف الفحص كل الملفات. النتيجة جزئية.');
  event('discovery','done',`ثُبت commit ${snapshot.commit.slice(0,12)}؛ ${stats.eligible} ملفات نصية مرشحة و${stats.excluded} مستبعدة.`,result.scope);
  let partial=snapshot.truncated,processed=0;
  for(const file of candidates){
   if(!running())return;
   if(processed>=maxFiles||Date.now()-started>=budget){partial=true;result.errors.push('وصل الفحص حد الملفات/الوقت/الحجم؛ الملفات المتبقية لم تفحص.');break;}
   processed++;stats.pending--;
   const url=base+'/blob/'+snapshot.commit+'/'+file.path.split('/').map(encodeURIComponent).join('/');
   if(file.size>(isNpmLockfile(file.path)?4*1024*1024:256*1024)){stats.excluded++;partial=true;if(stats.files.length<2000)stats.files.push({file:redact(file.path),url:redact(url),status:'excluded',reason:isNpmLockfile(file.path)?'يتجاوز حد lockfile البالغ 4MiB':'يتجاوز 256KiB'});event('fetch','warning','استبعاد ملف يتجاوز حد الحجم: '+file.path,url);continue;}
   if(stats.bytes+file.size>maxBytes){stats.pending++;partial=true;result.errors.push('بلغ الفحص حد حجم النصوص؛ الملفات المتبقية لم تجمع.');break;}
   event('fetch','running','قراءة ملف: '+file.path,url);
   try{
    const content=await read(signal=>reader.blob(file,signal));if(!running())return;
    stats.bytes+=Buffer.byteLength(content);if(job.dependencyAudit&&isNpmLockfile(file.path)){lockCount++;try{const lock=parseLockfile(file.path,content);installed.push(...lock.packages);lockIncomplete ||= lock.incomplete;}catch{lockErrors.push('تعذرت قراءة إصدارات مثبتة من '+file.path);}}const out=analyzeSource(file.path,content,url,store.ownedProject(job.owner_id,job.project_id)?.url);result.apiDiscovery!.files++;result.apiDiscovery!.excluded+=out.discovery.excluded;const mergeLimited=mergeApiServices(result.services,out.discovery.services);result.apiDiscovery!.limited=result.apiDiscovery!.limited||out.discovery.limited||mergeLimited;result.apiDiscovery!.origins=result.services.length;stats.analyzed++;result.checks!.push(...out.checks);result.findings.push(...out.findings);if(stats.files.length<2000)stats.files.push({file:redact(file.path),url:redact(url),status:'analyzed',bytes:Buffer.byteLength(content)});
    event('analyze','done',`حلل ${file.path}: ${out.checks.length} قواعد و${out.findings.length} ملاحظات.`,url);
   }catch(error){if(!running())return;if(error instanceof UnsupportedRepositoryFile){stats.excluded++;partial=true;if(stats.files.length<2000)stats.files.push({file:redact(file.path),url:redact(url),status:'excluded',reason:'ملف ثنائي أو ترميز غير UTF-8'});event('fetch','warning','استبعاد ملف ثنائي أو ترميز غير مدعوم: '+file.path,url);continue;}stats.failed++;partial=true;stats.files.push({file:redact(file.path),url:redact(url),status:'unavailable',reason:'تعذر جلب نص صالح أو انتهت مهلة/حد GitHub'});result.errors.push('تعذرت قراءة ملف من GitHub؛ توقف الجمع لحماية ميزانية API. أعد الفحص بعد مراجعة التوكن والحدود.');event('fetch','warning','تعذر جمع الملف؛ لم يعتبر فحصًا ناجحًا.',url);break;}
  }
  if(!stats.eligible){partial=true;result.errors.push('لا ملفات نصية مؤهلة ضمن الأنواع المدعومة. لم يفحص الكود.');}
  if(!running())return;
  const expectedLocks=candidates.filter(f=>isNpmLockfile(f.path)).length;
  const missingLocks=lockCount<expectedLocks||snapshot.truncated;
  const emptyAudit=(status:DependencyAudit['status'],error:string,reason?:DependencyAudit['unavailableReason']):DependencyAudit=>({status,unavailableReason:reason??(status==='not_enabled'?'configuration_required':'collection_error'),total:installed.length,queried:0,checkedAt:Date.now(),advisories:[],packages:[],errors:[error]});
  if(job.dependencyAudit){
   event('analyze','running','فحص إصدارات الاعتماديات المثبتة عبر OSV؛ لا يرسل المصدر أو توكن GitHub.');
   if(!lockCount||!installed.length)result.dependencyAudit=emptyAudit('unavailable',!lockCount?'لم يجمع lockfile npm مدعوم؛ أضف package-lock.json أو npm-shrinkwrap.json إلى الفرع.':'لم تستخرج إصدارات مؤهلة للاستعلام؛ راجع lockfile ومصادر الحزم.',expectedLocks===0?'configuration_required':'collection_error');
   else try{result.dependencyAudit=await read(signal=>auditDependencies(installed,options.osvTransport,signal));}catch{result.dependencyAudit=emptyAudit('unavailable','تعذر إكمال اتصال OSV ضمن ميزانية الفحص.');}
   if(lockIncomplete||lockErrors.length||missingLocks){result.dependencyAudit.status=result.dependencyAudit.queried?'partial':'unavailable';result.dependencyAudit.errors.push(...lockErrors,...(missingLocks?[`لم تجمع كل ملفات lock المعروفة أو كانت الشجرة مختصرة (${lockCount}/${expectedLocks})؛ جرد الاعتماديات جزئي.`]:[]),...(lockIncomplete?['بعض إدخالات lockfile غير مؤهلة أو غير مثبتة؛ التغطية جزئية.']:[]));}
   if(result.dependencyAudit.status!=='completed')partial=true;
  }else result.dependencyAudit=emptyAudit('not_enabled','لم يُفعّل فحص OSV وإرسال أسماء/إصدارات الحزم لهذا التشغيل.');
  if(!running())return;
  const dependency=dependencyResults(result.dependencyAudit,base,file=>base+'/blob/'+snapshot.commit+'/'+file.split('/').map(encodeURIComponent).join('/'));result.checks!.push(...dependency.checks);result.findings.push(...dependency.findings);
  event('analyze',result.dependencyAudit.status==='completed'?'done':'warning',`OSV: ${result.dependencyAudit.queried} إصدار استُعلم عنه، ${result.dependencyAudit.advisories.length} نشرات مطابقة؛ الحالة ${result.dependencyAudit.status}.`);
  event('analyze','done',`اكتشاف API تلقائي: ${result.services.length} أصول من ${result.apiDiscovery!.files} ملفات؛ دون إدخال روابط يدويًا أو إرسال طلبات للخدمات.`);
  event('analyze','running',job.runtimeSecurity?'فحص استجابة التطبيق المنشور ضمن النطاق الموثق.':'تسجيل نطاق الفحص: فحص التطبيق المنشور لم يفعّل.');
  try{const runtime=await read(signal=>runRuntimeSecurity(store,job,signal,options.runtimeCollect));result.runtimeSecurity=runtime.runtime;result.checks!.push(...runtime.checks);result.findings.push(...runtime.findings);if(job.runtimeSecurity&&runtime.runtime.status!=='completed')partial=true;}
  catch{if(!running())return;partial=true;result.runtimeSecurity={status:'unavailable',detail:'تعذر جمع استجابة التطبيق الموثق ضمن الميزانية؛ لم يحتسب نجاحًا.'};result.checks!.push({id:'repo.runtime|'+base,rule:'repo.runtime',category:'security',status:'unavailable',unavailableReason:'collection_error',weight:2,title:'فحص التطبيق المنشور — HTTP',url:base,evidence:result.runtimeSecurity.detail,recommendation:'راجع توثيق النطاق واتصال HTTP ثم أعد الفحص.'});}
  if(!running())return;
  event('analyze','running','فحص HTTP تلقائي للـAPI المكتشف: HEAD وOPTIONS بلا حسابات أو مفاتيح أو موارد بيانات.');
  const automatic=await runAutomaticApiHttp(result.services,{running,signal:AbortSignal.timeout(Math.max(1,budget-(Date.now()-started))),budgetMs:budget-(Date.now()-started),transport:options.apiHttpTransport,onCheck:(c,summary)=>{result.apiHttp=summary;const index=result.checks!.findIndex(old=>old.id===c.id);if(index>=0)result.checks![index]=c;else result.checks!.push(c);event('analyze',c.status==='unavailable'?'warning':'done',c.title+': '+(c.execution?.observed??c.evidence),c.url);}});
  result.apiHttp=automatic.summary;result.findings.push(...automatic.findings);
  if(automatic.summary.status==='partial')partial=true;
  if(job.apiTests){
   event('analyze','running','تنفيذ مصفوفة القراءة الاختيارية التي طلبتها: المالكان والحساب الآخر والزائر.');
   const api=await runApiTests(store,job,AbortSignal.timeout(Math.max(1,budget-(Date.now()-started))),options.apiTransport,c=>{const index=result.checks!.findIndex(old=>old.id===c.id);if(index>=0)result.checks![index]=c;else result.checks!.push(c);event('analyze',c.status==='unavailable'?'warning':'done',c.title+': '+c.evidence,c.url);});
   result.findings.push(...api.findings);if(api.checks.some(c=>c.status==='unavailable'))partial=true;
  }
  if(!running())return;
  event('complete','done',`انتهى تحليل المستودع: ${stats.analyzed} ملفات مفحوصة، ${stats.pending} لم تجمع.`,result.scope);
  if(running())store.finishScan(job.id,partial?'partial':'completed',normalizeLegacyResult(result));
 }catch{if(!running())return;for(const c of result.checks??[])if(c.execution?.state==='planned'){c.execution.state='completed';c.execution.observed='لم يرسل طلب';c.unavailableReason='collection_error';c.evidence='تعذر GitHub قبل الوصول إلى مرحلة API؛ هذه الحالة لم تنفذ.';}result.errors.push('تعذر الوصول إلى المستودع/الفرع أو فُقد ربطه أو انتهت مهلة GitHub. راجع التوكن وصلاحية Contents: read ثم أعد الفحص.');event('complete','warning',result.errors.at(-1)!);store.finishScan(job.id,stats.analyzed?'partial':'failed',normalizeLegacyResult(result),'تعذر إكمال قراءة مستودع GitHub');}
}
