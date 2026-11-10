import type {AuditCheck,Category,ScanResult} from './types';
export const SCORE_VERSION='aegis-checklist-v3';
export const categoryInfo:{id:Category;label:string;subtitle:string}[]=[
 {id:'seo',label:'SEO',subtitle:'تحسين صفحات البحث'},
 {id:'geo',label:'GEO / AEO',subtitle:'مؤشرات جاهزية المحتوى'},
 {id:'performance',label:'Performance',subtitle:'أداء نقل HTTP فقط'},
 {id:'accessibility',label:'Accessibility',subtitle:'قواعد الوصول في HTML'},
 {id:'security',label:'Security',subtitle:'الدفاعات والأسرار العامة'},
 {id:'technical',label:'Technical',subtitle:'الاستجابة وبنية المستند'},
 {id:'ux',label:'UX / UI',subtitle:'مؤشرات الاستخدام الهيكلية'}
];
export type ScoreMetric={score:number|null;coverage:number|null;passed:number;failed:number;unavailable:number;notApplicable:number;executed:number;planned:number;passedWeight:number;executedWeight:number};
export type ScoreSummary={overall:ScoreMetric;categories:(ScoreMetric&{id:Category;label:string;subtitle:string})[];legacy:boolean;version:string};
function metric(checks:AuditCheck[]):ScoreMetric{
 const valid=checks.filter(c=>Number.isFinite(c.weight)&&c.weight>0);
 const passed=valid.filter(c=>c.status==='pass'),failed=valid.filter(c=>c.status==='fail');
 const unavailable=valid.filter(c=>c.status==='unavailable').length,notApplicable=valid.filter(c=>c.status==='not_applicable').length;
 const passedWeight=passed.reduce((n,c)=>n+c.weight,0),executedWeight=passedWeight+failed.reduce((n,c)=>n+c.weight,0);
 const executed=passed.length+failed.length,planned=executed+unavailable;
 return {score:executedWeight?Math.round(passedWeight/executedWeight*100):null,coverage:planned?Math.round(executed/planned*100):null,passed:passed.length,failed:failed.length,unavailable,notApplicable,executed,planned,passedWeight,executedWeight};
}
export function summarizeChecks(checks:AuditCheck[]):ScoreSummary{
 // Same rule on different pages remains a different observation. A repeated task cannot inflate the denominator.
 const unique=[...new Map(checks.map(c=>[`${c.url}|${c.rule}`,c])).values()];
 return {overall:metric(unique),categories:categoryInfo.map(c=>({...c,...metric(unique.filter(x=>x.category===c.id))})),legacy:false,version:SCORE_VERSION};
}
export function scoreReport(result?:ScanResult|null):ScoreSummary{
 if(!result||!['aegis-checklist-v1','aegis-checklist-v2',SCORE_VERSION].includes(result.scoreVersion??'')||!Array.isArray(result.checks)||(result.pages.length>0&&result.checks.length===0))return {...summarizeChecks([]),legacy:Boolean(result)};
 const summary=summarizeChecks(result.checks);summary.version=result.scoreVersion!;
 if(result.checks.some(c=>['performance.lcp','performance.cls'].includes(c.rule)&&['pass','fail'].includes(c.status)))summary.categories.find(c=>c.id==='performance')!.subtitle='قياسات متصفح مختبرية';
 if(result.checks.some(c=>c.rule.startsWith('axe.')))summary.categories.find(c=>c.id==='accessibility')!.subtitle='HTML + axe في المتصفح';
 if(result.repository){summary.categories.find(c=>c.id==='security')!.subtitle='قواعد أمان الكود الثابتة';summary.categories.find(c=>c.id==='technical')!.subtitle='إعدادات الكود والحزم';for(const c of summary.categories)if(!['security','technical'].includes(c.id))c.subtitle='غير مقاس بفحص المستودع';}
 return summary;
}
