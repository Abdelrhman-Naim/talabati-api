import {requestResource} from '../network';
import type {Severity} from '../types';
import type {InstalledPackage} from './dependencies';
export type Advisory={id:string;aliases:string[];name:string;version:string;summary:string;severity:Severity;severityKnown:boolean;fixedVersions:string[];url:string;detailAvailable:boolean};
export type DependencyAudit={status:'completed'|'partial'|'unavailable'|'not_enabled';unavailableReason?:'configuration_required'|'collection_error';total:number;queried:number;checkedAt:number;advisories:Advisory[];packages:(InstalledPackage&{checked:boolean;complete:boolean;vulnerabilityIds:string[]})[];errors:string[]};
export type OsvTransport=(url:string,options:{method:'GET'|'POST';body?:string;signal?:AbortSignal})=>Promise<Record<string,unknown>>;
const transport:OsvTransport=async(url,options)=>{const r=await requestResource(url,{...options,headers:{'content-type':'application/json',accept:'application/json'}});if(r.status!==200)throw new Error('OSV لم يعد استجابة ناجحة');const data:unknown=JSON.parse(r.body);if(!data||typeof data!=='object'||Array.isArray(data))throw new Error('استجابة OSV غير صالحة');return data as Record<string,unknown>;};
export async function auditDependencies(input:InstalledPackage[],fetchJson:OsvTransport=transport,signal?:AbortSignal):Promise<DependencyAudit>{
 const unique=[...new Map(input.map(p=>[p.name+'@'+p.version,p])).values()];
 const report:DependencyAudit={status:'completed',total:unique.length,queried:0,checkedAt:Date.now(),advisories:[],packages:unique.slice(0,2000).map(p=>({...p,checked:false,complete:false,vulnerabilityIds:[]})),errors:[]};
 if(unique.length>2000){report.status='partial';report.errors.push('بلغ حد OSV البالغ 2000 إصدار فريد؛ لم تستعلم بقية الإصدارات.');}
 let details=0;
 for(let offset=0;offset<report.packages.length;offset+=50){
  if(signal?.aborted){report.status=report.queried?'partial':'unavailable';report.errors.push('توقف استعلام OSV أو انتهت ميزانيته.');break;}
  const batch=report.packages.slice(offset,offset+50);
  try{
   const data=await fetchJson('https://api.osv.dev/v1/querybatch',{method:'POST',body:JSON.stringify({queries:batch.map(p=>({package:{name:p.name,ecosystem:'npm'},version:p.version}))}),signal});
   if(!Array.isArray(data.results)||data.results.length!==batch.length)throw new Error('OSV batch غير مطابق');
   for(let i=0;i<batch.length;i++){
    const row=data.results[i];if(!row||typeof row!=='object'||Array.isArray(row)||Object.keys(row).some(k=>!['vulns','next_page_token'].includes(k))){report.status='partial';continue;}const record=row as Record<string,unknown>,p=batch[i];
    if(record.next_page_token!==undefined&&typeof record.next_page_token!=='string'){report.status='partial';continue;}
    if(record.vulns!==undefined&&!Array.isArray(record.vulns)){report.status='partial';continue;}
    p.checked=true;report.queried++;p.complete=!record.next_page_token;
    if(!p.complete){report.status='partial';report.errors.push('استجابة OSV تحتوي صفحات إضافية لم تجمع؛ لا تعتبر نتيجة خالية من الثغرات.');}
    for(const entry of (record.vulns as unknown[]|undefined)??[]){
     const id=entry&&typeof entry==='object'?(entry as {id?:unknown}).id:undefined;if(typeof id!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,150}$/.test(id)){p.complete=false;report.status='partial';continue;}
     if(p.vulnerabilityIds.includes(id))continue;
     let detail:Record<string,unknown>|undefined;
     if(details<50){details++;try{detail=await fetchJson('https://api.osv.dev/v1/vulns/'+encodeURIComponent(id),{method:'GET',signal});}catch{report.status='partial';}}
     else report.status='partial';
     if(detail&&detail.id!==id){detail=undefined;report.status='partial';}
     if(typeof detail?.withdrawn==='string'&&!Number.isNaN(Date.parse(detail.withdrawn)))continue;
     if(detail?.withdrawn){detail=undefined;report.status='partial';}
     p.vulnerabilityIds.push(id);
     const severityValue=String((detail?.database_specific as {severity?:unknown}|undefined)?.severity??'').toLowerCase(),known=['critical','high','moderate','medium','low'].includes(severityValue);
     const severity:Severity=known?(severityValue==='moderate'?'medium':severityValue as Severity):'info';
     const fixed:string[]=[];
     for(const affected of Array.isArray(detail?.affected)?detail.affected:[]){if(affected?.package?.name!==p.name||affected?.package?.ecosystem!=='npm')continue;for(const range of Array.isArray(affected.ranges)?affected.ranges:[])if(range.type==='SEMVER')for(const event of Array.isArray(range.events)?range.events:[])if(typeof event.fixed==='string'&&/^\d+\.\d+\.\d+[\w.+-]*$/.test(event.fixed)&&!fixed.includes(event.fixed))fixed.push(event.fixed);}
     report.advisories.push({id,aliases:(Array.isArray(detail?.aliases)?detail.aliases:[]).filter((x:unknown):x is string=>typeof x==='string'&&/^[A-Za-z0-9_.-]{1,150}$/.test(x)).slice(0,20),name:p.name,version:p.version,summary:typeof detail?.summary==='string'?detail.summary.slice(0,500):'نشرة مطابقة في OSV؛ راجع المصدر لتفاصيل الخطورة.',severity,severityKnown:known,fixedVersions:fixed.slice(0,20),url:'https://osv.dev/vulnerability/'+encodeURIComponent(id),detailAvailable:!!detail});
     if(report.advisories.length>=500){report.status='partial';p.complete=false;break;}
    }
    if(report.advisories.length>=500)break;
   }
   if(report.advisories.length>=500){report.errors.push('بلغ حد عرض 500 نشرة؛ التغطية جزئية.');break;}
  }catch{report.status=report.queried?'partial':'unavailable';report.errors.push('تعذر الاتصال بـOSV أو قراءة استجابة صالحة؛ لا تُحسب الطلبات الفاشلة نجاحًا.');break;}
 }
 if(report.packages.some(p=>!p.checked||!p.complete)&&report.status==='completed')report.status='partial';
 return report;
}
