import {discoverApiReferences,apiReferenceResults,mergeApiServices} from './api-discovery';
import {normalizeCrawlUrl} from './crawler';
import {load} from 'cheerio';
import {createHash} from 'node:crypto';
import {redact} from './network';
import {evaluateChecks} from './checks';
import {SCORE_VERSION} from './scoring';
import type {AuditOutput,Category,Coverage,Finding,HttpPage,Severity,Service} from './types';

export const coverage:Coverage[]=[
  {id:'seo',label:'SEO',status:'partial',detail:'بيانات الصفحة والعناوين والروابط المرجعية من HTML؛ دون فهرسة محرك بحث.'},
  {id:'accessibility',label:'إمكانية الوصول',status:'partial',detail:'قواعد HTML للأسماء واللغة؛ لم يشغل axe أو تدقيق لوحة المفاتيح والتباين.'},
  {id:'security',label:'الأمان',status:'partial',detail:'تحليل CSP وHSTS والتضمين والكوكيز وCORS ونماذج كلمات المرور والمحتوى المختلط وSRI وأنماط الأسرار؛ صلاحيات API وRLS غير مختبرة.'},
  {id:'technical',label:'التقني',status:'partial',detail:'حالات HTTP وعناصر الصفحات المجموعة؛ دون تنفيذ JavaScript.'},
  {id:'ux',label:'UX / UI',status:'partial',detail:'إعداد viewport وقواعد DOM فقط؛ لا تحليل بصري أو اختبار مستخدمين.'},
  {id:'geo',label:'GEO / AEO',status:'partial',detail:'مؤشرات JSON-LD وهوية الناشر والتاريخ وهيكلة النص؛ ليست قياس ظهور في AI.'},
  {id:'performance',label:'الأداء',status:'partial',detail:'حجم HTML وزمن جلب HTTP فقط؛ LCP وCLS وINP غير مقاسة.'}
];
export function analyze(page:HttpPage):AuditOutput{
  const $=load(page.body);const findings:Finding[]=[];const services:Service[]=[];const origin=new URL(page.url).origin;
  let documentBase=page.url;try{const base=$('base[href]').first().attr('href');if(base){const resolved=new URL(base,page.url);if(['http:','https:'].includes(resolved.protocol))documentBase=resolved.href;}}catch{}
  const checks=evaluateChecks(page);
  const negatives:Record<string,string>={'seo.title':'عنوان الصفحة مفقود','seo.description':'وصف محركات البحث مفقود','seo.canonical':'الرابط المرجعي يحتاج مراجعة','seo.h1':'راجع العنوان الرئيسي للصفحة','a11y.lang':'لغة الصفحة غير محددة','a11y.image-alt':'صور بلا خاصية نص بديل','a11y.input-name':'حقول تحتاج أسماء واضحة','security.secret':'مرجع لمفتاح مرتفع الصلاحية في مصدر عام'};
  for(const c of checks.filter(c=>c.status==='fail'))findings.push({id:createHash('sha256').update(c.rule+'|'+c.url).digest('hex').slice(0,20),rule:c.rule,category:c.category,severity:c.severity??'low',confidence:c.category==='geo'||c.security?.basis==='indicator'?'medium':'high',title:negatives[c.rule]??('يحتاج تحسين: '+c.title),security:c.security,description:c.security?.impact??('لم تستوفِ الصفحة هذه القاعدة المحلية ضمن الفحص المتاح. '+c.evidence),url:c.url,evidence:c.evidence,recommendation:c.recommendation,checks:c.security?.verification??['أعد فحص القاعدة '+c.rule+' على نفس الصفحة بعد التغيير.','تحقق من السلوك المطلوب؛ نجاح القاعدة لا يثبت سلامة كل التطبيق.']});
  for(const match of page.body.matchAll(/https?:\/\/[^\s"'<>`\\)]+/g)){
    try{const u=new URL(match[0]);if(u.origin===origin)continue;if(!services.some(s=>s.origin===u.origin))services.push({origin:redact(u.origin),type:u.hostname.endsWith('.supabase.co')?'Supabase':u.hostname.includes('firebase')?'Firebase':'مرجع خارجي',source:redact(page.url),status:'observed_reference',paths:[]});const service=services.find(s=>s.origin===u.origin)!;const path=redact(u.pathname).slice(0,160);if(!service.paths.includes(path)&&service.paths.length<5)service.paths.push(path);}catch{}
    if(services.length>=30)break;
  }
  const observedLimited=mergeApiServices(services,page.browser?.services??[]);
  const discovery=discoverApiReferences((/javascript|ecmascript/i.test(page.headers['content-type']??'')||/\.[cm]?js(?:[?#]|$)/i.test(page.url))?'collected.js':'collected.html',page.body,page.url,page.url);
  const mergeLimited=mergeApiServices(services,discovery.services);checks.push(...discovery.checks);findings.push(...discovery.findings);
  const observed=apiReferenceResults(services.filter(s=>s.status==='observed_request'&&/API|Supabase/i.test(s.type)),page.url);checks.push(...observed.checks);findings.push(...observed.findings);
  const sameOrigin=(selector:string,attribute:string)=>$(selector).toArray().flatMap(el=>{try{const value=$(el).attr(attribute)??'';if(attribute==='href'){const href=normalizeCrawlUrl(value,documentBase,origin);return href?[href]:[];}const u=new URL(value,documentBase);if(u.origin!==origin)return [];u.hash='';return [u.href];}catch{return [];}});
  return {apiDiscovery:{files:1+(page.browser?.apiDiscovery?.files??0),origins:services.filter(s=>/API|Supabase/i.test(s.type)).length,excluded:discovery.excluded+(page.browser?.apiDiscovery?.excluded??0),limited:discovery.limited||mergeLimited||observedLimited||Boolean(page.browser?.apiDiscovery?.limited)},findings,services,links:[...new Set(sameOrigin('a[href]','href'))],scripts:[...new Set(sameOrigin('script[src]','src'))].slice(0,3),coverage:structuredClone(coverage),checks,scoreVersion:SCORE_VERSION};
}
