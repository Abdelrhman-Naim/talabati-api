import {createHash} from 'node:crypto';
import {requestResource,validateTarget,redact} from './network';
import {securityChecks} from './security';
import type {Service,AuditCheck,Finding,ScanResult} from './types';
export type ApiHttpSummary={status:'completed'|'partial'|'no_targets';targets:number;attempted:number;responses:number;excluded:number;limited:boolean};
export type ApiHttpTransport=typeof requestResource;
export const identityCapability={id:'api-identities',label:'عزل حسابين وRLS الحي',state:'not_requested' as const,detail:'اختبار اختياري لم يُطلب. الفحص التلقائي يفحص مراجع API وHTTP، ولا يختلق هويات أو يثبت صلاحيات RLS. لا يدخل هذا الخيار في درجة الفحص أو تغطيته.'};
export async function runAutomaticApiHttp(services:Service[],options:{running:()=>boolean;signal?:AbortSignal;transport?:ApiHttpTransport;budgetMs?:number;onCheck?:(c:AuditCheck,summary:ApiHttpSummary)=>void}){
 const checks:AuditCheck[]=[],findings:Finding[]=[],summary:ApiHttpSummary={status:'completed',targets:0,attempted:0,responses:0,excluded:0,limited:false};
 const started=Date.now(),budget=Math.max(1,Math.min(20000,options.budgetMs??20000)),targets=new Set<string>();
 for(const s of services){if(!/API|Supabase/i.test(s.type))continue;try{const raw=new URL(s.origin);if(raw.username||raw.password||raw.href!==raw.origin+'/')throw new Error('invalid origin');const u=validateTarget(raw.href);if(targets.has(u.origin))continue;if(targets.size>=8){summary.limited=true;continue;}targets.add(u.origin);}catch{summary.excluded++;}}
 summary.targets=targets.size;if(!targets.size){summary.status='no_targets';return {checks,findings,summary};}
 const pending:AuditCheck[]=[];
 for(const origin of targets){const host=new URL(origin).hostname,url=origin+(host.endsWith('.supabase.co')?'/rest/v1/':'/');for(const method of ['HEAD','OPTIONS']){const id=createHash('sha256').update(url+'|'+method).digest('hex').slice(0,20),cors=method==='OPTIONS';pending.push({id:'api-http|'+id,rule:cors?'security.api-http-cors':'technical.api-http-response',category:cors?'security':'technical',title:cors?'استجابة CORS لطلب Origin غير موثوق':'استجابة HTTP أساسية من API',url,status:'unavailable',unavailableReason:'collection_error',weight:cors?2:1,evidence:'لم تبدأ محاولة طلب بيانات HTTP الوصفية بعد.',recommendation:'راجع الاستجابة والمهلة؛ لا تستنتج صلاحيات البيانات من هذا الفحص.',execution:{state:'planned',engine:'api-http/0.12',method,identity:'بدون حساب أو مفتاح',resource:'بيانات HTTP وصفية',expected:cors?'استجابة preflight دون السماح باعتمادات Origin التجريبي':'استجابة HTTP دون اتباع تحويل أو قراءة مورد بيانات',observed:'بانتظار التنفيذ',attempted:false,at:Date.now()},security:{group:'api',basis:'not_tested',method:'HEAD/OPTIONS تلقائي بلا اعتمادات أو جسم طلب؛ لا طلبات GET إلى جداول أو موارد بيانات.',impact:'لا يختبر عزل المستخدمين أو حالة RLS أو كل مسارات API.',fixSteps:['راجع إعدادات CORS ورؤوس API في بيئة الاختبار.'],verification:['أعد HEAD/OPTIONS على نفس مسار البيانات الوصفية.'],references:[]}});}}
 for(const c of pending){checks.push(c);options.onCheck?.(c,summary);}
 for(const c of pending){
  const remaining=budget-(Date.now()-started);
  if(!options.running()||options.signal?.aborted||remaining<=0){summary.limited=true;summary.status='partial';c.execution!.state=!options.running()?'cancelled':'completed';c.execution!.observed='لم يرسل: إلغاء أو انتهاء ميزانية الوقت';c.evidence='لم يُرسل الطلب بسبب الإلغاء أو المهلة؛ لم يحسب نجاحًا.';options.onCheck?.(c,summary);continue;}
  const probe='https://aegis-untrusted.invalid',headers:Record<string,string>={accept:'*/*','cache-control':'no-cache'};if(c.execution!.method==='OPTIONS'){headers.origin=probe;headers['access-control-request-method']='GET';}
  c.execution!.attempted=true;c.execution!.at=Date.now();c.execution!.observed='طلب بيانات وصفية جارٍ';c.evidence='جرت محاولة HEAD/OPTIONS بلا أسرار أو موارد بيانات.';summary.attempted++;options.onCheck?.(c,summary);
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),Math.min(4000,remaining)),watch=setInterval(()=>{if(!options.running())controller.abort();},50);
  try{
   const signal=options.signal?AbortSignal.any([controller.signal,options.signal]):controller.signal;
   const response=await (options.transport??requestResource)(c.url,{origin:new URL(c.url).origin,method:c.execution!.method as 'HEAD'|'OPTIONS',headers,maxResponseBytes:4096,signal});
   if(signal.aborted||!options.running())throw new Error('cancelled');
   summary.responses++;c.execution!.httpStatus=response.status;c.execution!.elapsedMs=response.elapsedMs;c.execution!.bytes=response.bytes;c.execution!.observed=`HTTP ${response.status}؛ ${response.elapsedMs} ms؛ ${response.bytes} بايت؛ لم يُحفظ جسم الاستجابة`;
   if(response.url!==c.url||response.status>=300&&response.status<400){c.evidence='تحويل/وجهة غير مطابقة؛ لم يُتبع ولم يُعتبر نجاحًا.';}
   else if(c.execution!.method==='HEAD'){
    c.status='pass';delete c.unavailableReason;c.evidence=`استجاب API بـHTTP ${response.status} لطلب HEAD بلا حساب. نجاح جمع الاستجابة فقط؛ 401/403 لا يثبت عزل البيانات.`;
    for(const h of securityChecks({...response,body:'',rawBody:undefined}).filter(h=>['security.hsts','security.nosniff','security.cookies'].includes(h.rule))){h.id='api-http-header|'+h.id;h.rule='security.api-http-'+h.rule.slice(9);h.title='API — '+h.title;h.evidence=redact(h.evidence)+'؛ من طلب HEAD الوصفي فقط.';if(h.security){h.security.group='api';h.security.method='تحليل رؤوس استجابة HEAD فعلية؛ لا اختبار صلاحيات.';}checks.push(h);options.onCheck?.(h,summary);if(h.status==='fail')findings.push({id:h.id,rule:h.rule,category:'security',severity:h.severity??'low',confidence:'medium',title:h.title,description:h.security?.impact??'',url:h.url,evidence:h.evidence,recommendation:h.recommendation,checks:h.security?.verification??[],security:h.security});}
   }else if(response.status<200||response.status>=300){c.evidence=`HTTP ${response.status} لا يوفر preflight صالحًا على هذا المسار؛ CORS غير محسوم، وليس فشل تسجيل دخول.`;}
   else{
    const h=response.headers,origin=h['access-control-allow-origin']??'',credentials=(h['access-control-allow-credentials']??'').toLowerCase()==='true',reflected=origin===probe&&credentials,invalidWildcard=origin==='*'&&credentials;
    c.status=reflected||invalidWildcard?'fail':'pass';delete c.unavailableReason;c.severity=reflected?'high':'medium';
    c.evidence=reflected?'أعاد preflight أصل الاختبار غير الموثوق مع allow-credentials:true؛ مؤشر إعداد CORS يحتاج مراجعة، وليس إثبات قراءة بيانات.':invalidWildcard?'أعاد preflight أصل * مع allow-credentials:true؛ تركيب غير صالح للطلبات المعتمدة في المتصفح، وليس إثبات استغلال.':'لم يرصد preflight إقران اعتمادات بأصل الاختبار؛ الحكم يخص هذا المسار وOrigin فقط، ولا يثبت تفويض البيانات.';
    c.recommendation='استخدم قائمة Origins موثوقة عند السماح بالاعتمادات، واختبرها في المتصفح مع صلاحيات حقيقية.';
    if(c.status==='fail')findings.push({id:c.id,rule:c.rule,category:'security',severity:c.severity,confidence:'medium',title:c.title,description:c.security!.impact,url:c.url,evidence:c.evidence,recommendation:c.recommendation,checks:c.security!.verification,security:c.security});
   }
   c.execution!.state='completed';if(c.security)c.security.basis=c.status==='unavailable'?'not_tested':'indicator';
  }catch{c.status='unavailable';c.unavailableReason='collection_error';c.execution!.state=options.running()?'completed':'cancelled';c.execution!.observed='لا استجابة مكتملة موثوقة';c.evidence='تعذر الاتصال أو انتهت المهلة أو أُلغي الفحص؛ لم تُختبر بيانات المستخدمين.';}
  finally{clearTimeout(timer);clearInterval(watch);}
  if(c.status==='unavailable')summary.status='partial';options.onCheck?.(c,summary);
 }
 if(summary.limited||summary.excluded)summary.status='partial';
 return {checks,findings,summary};
}
