import {tomlLines} from './toml-lines';
import {createHash} from 'node:crypto';
import {redact} from '../redaction';
import {sqlSecurity} from './sql-security';
import type {AuditCheck,Finding,Severity} from '../types';
export function advancedSecurity(file:string,body:string,url:string){
 const checks:AuditCheck[]=[],findings:Finding[]=[];
 const add=(rule:string,title:string,status:AuditCheck['status'],line:number,evidence:string,fix:string,high=false,resource='')=>{
  const severity:Severity=high?'high':'medium',id=createHash('sha256').update([rule,file,line,resource,checks.length].join('|')).digest('hex').slice(0,20);
  const check:AuditCheck={id:'advanced|'+id,rule,title,status,category:'security',weight:high?4:2,severity,file:redact(file),line,url:redact(url),evidence:redact(evidence+(resource?' المورد: '+resource:'')).slice(0,900),recommendation:fix,...(status==='unavailable'?{unavailableReason:'collection_error' as const}:{}),security:{group:'api',basis:status==='unavailable'?'not_tested':'indicator',method:'قراءة محلية لتعريفات SQL/TOML؛ دون تنفيذ أو اتصال بقاعدة البيانات. قواعد محددة وليست محلل PostgreSQL كاملًا.',impact:'يحتاج الحكم مراجعة قصد البيانات والأدوار وحالة النشر؛ لا يثبت استغلالًا فعليًا.',fixSteps:[fix],verification:['راجع الملف والسطر وcommit.','اختبر الأدوار المتوقعة في بيئة اختبار موثقة ثم أعد الفحص.'],references:[{label:'PostgreSQL CREATE POLICY',url:'https://www.postgresql.org/docs/current/sql-createpolicy.html'},{label:'PostgreSQL SECURITY DEFINER',url:'https://www.postgresql.org/docs/current/sql-createfunction.html'}]}};checks.push(check);
  if(status==='fail')findings.push({id:'advanced|'+id,rule,category:'security',severity,confidence:'medium',title,description:check.security!.impact,url:check.url,evidence:check.evidence,recommendation:fix,checks:check.security!.verification,file:check.file,line,security:check.security});
 };
 if(/\.sql$/i.test(file)){const out=sqlSecurity(body);add('repo.sql.parse','اكتمال تجزئة SQL النصية',out.complete?'pass':'unavailable',1,out.complete?'اكتملت قراءة التعليقات والاقتباسات وأجسام dollar-quote؛ لا يثبت ذلك صحة SQL الكاملة.':'اقتباس أو تعليق أو أقواس غير مكتملة، أو حد تحليل SQL (60000 خطوة/250 ملاحظة)؛ لم تحتسب قواعد SQL نجاحًا.','راجع الصياغة بمحلل PostgreSQL ثم أعد الفحص.');if(out.complete)for(const o of out.observations)add(o.rule,o.title,o.status,o.line,o.evidence,o.fix,o.high,o.resource);}
 if(/(?:^|\/)supabase\/config\.toml$/i.test(file)){
  const masked=tomlLines(body);if(!masked.complete)add('repo.supabase-config-parse','اكتمال قراءة إعداد Supabase','unavailable',1,'قيمة نصية غير مكتملة؛ لم تفترض سلامة verify_jwt.','راجع TOML ثم أعد الفحص.');
  else {let inFunction=false;for(const [i,line]of masked.lines.entries()){const clean=line.trim();if(clean.startsWith('[')){inFunction=/^\[functions\.[\w-]+\]$/.test(clean);if(/^\[functions\./.test(clean)&&!inFunction)add('repo.supabase-config-shape','صيغة اسم Edge Function غير مدعومة','unavailable',i+1,'الصيغة تحتاج محلل TOML كاملًا؛ لم تحتسب verify_jwt نجاحًا.','راجع إعداد الدالة يدويًا واختبرها.');}if(inFunction&&/^verify_jwt\s*=\s*(true|false)\s*$/.test(clean))add('repo.supabase-verify-jwt','التحقق من JWT في Edge Function',!/=\s*false/.test(clean)?'pass':'fail',i+1,!/=\s*false/.test(clean)?'verify_jwt = true مرصود؛ لا يثبت التفويض داخل الدالة.':'verify_jwt = false مرصود؛ قد يكون webhook عامًا مقصودًا ويحتاج تحقق توقيع بديل.','فعّل التحقق حيث يلزم، أو تحقق من توقيع webhook وسياقه وحدود الاستخدام داخل الدالة.',true);}}
 }

 return {checks,findings};
}
