import {collect} from '../network';import {analyze} from '../audit';
import type {Store} from '../db';import type {Scan,HttpPage,AuditCheck,ScanResult} from '../types';
export type RuntimeCollector=(url:string,origin:string,signal?:AbortSignal,allowed?:(url:string)=>boolean)=>Promise<HttpPage>;
export async function runRuntimeSecurity(store:Store,job:Scan,signal?:AbortSignal,loader:RuntimeCollector=(url,origin,signal,allowUrl)=>collect(url,origin,0,{signal,allowUrl})){
 const project=store.ownedProject(job.owner_id,job.project_id);
 const check=(detail:string):AuditCheck=>({id:'repo.runtime|'+job.project_id,rule:'repo.runtime',category:'security',status:'unavailable',unavailableReason:'configuration_required',weight:2,title:'فحص التطبيق المنشور — HTTP',url:project?.url??'',evidence:detail,recommendation:'وثّق نطاق الموقع ثم فعّل فحص التطبيق المنشور عند بدء التحليل العميق.'});
 if(!job.runtimeSecurity)return {runtime:{status:'not_enabled',detail:'لم يفعّل فحص التطبيق المنشور لهذه المهمة.'} as NonNullable<ScanResult['runtimeSecurity']>,checks:[check('تحليل GitHub لم يطلب فحص رابط التطبيق. فعّل الخيار بعد إثبات النطاق.')],findings:[]};
 if(!project||project.verified_until<=Date.now())return {runtime:{status:'unavailable',detail:'انتهى توثيق النطاق؛ لم يُرسل طلب إلى التطبيق.'} as NonNullable<ScanResult['runtimeSecurity']>,checks:[check('انتهى توثيق نطاق الموقع؛ أعد إثباته قبل إرسال طلبات.')],findings:[]};
 const origin=new URL(project.url).origin;
 const allowed=(url:string)=>{const live=store.ownedProject(job.owner_id,job.project_id);return Boolean(live&&live.verified_until>Date.now()&&store.isRunning(job.id)&&new URL(url).origin===origin);};
 if(!allowed(project.url))throw new Error('انتهى حجز العامل أو تغير نطاقه');
 const page=await loader(project.url,origin,signal,allowed);signal?.throwIfAborted();if(!allowed(page.url))throw new Error('تغير نطاق الفحص أو انتهى توثيقه');
 const analyzed=analyze(page);const checks=analyzed.checks.filter(c=>['security','technical'].includes(c.category));for(const c of checks)if(c.status==='unavailable')c.unavailableReason='unsupported';
 checks.push({id:'repo.runtime|'+project.url,rule:'repo.runtime',category:'technical',status:'pass',weight:1,title:'جمع استجابة التطبيق المنشور وتحليلها',url:project.url,evidence:`جُمعت استجابة HTTP ${page.status}؛ نُفذت قواعد الاستجابة وHTML. لا اختبار تفويض/API أو RLS نشط.`,recommendation:'راجع نتائج الأمان الفعلية منفصلة عن نجاح جمع الاستجابة.'});
 return {runtime:{status:'completed',url:page.url,checkedAt:Date.now(),detail:`نُفذ جمع HTTP وقواعد الأمان على الموقع الموثق (HTTP ${page.status})؛ لا تشغيل للمستودع أو اختبار استغلال/صلاحيات نشط.`} as NonNullable<ScanResult['runtimeSecurity']>,checks,findings:analyzed.findings.filter(f=>['security','technical'].includes(f.category))};
}
