import {discoverApiReferences} from '../api-discovery';
import {advancedSecurity} from './advanced-security';
import {analyzeJavaScript,supportsJavaScript} from './ast';
import {createHash} from 'node:crypto';
import {secretCount} from '../secret-patterns';
import {redact} from '../redaction';
import type {AuditCheck,Finding,Severity,CheckStatus} from '../types';
export function eligibleSource(path:string){if(/(?:^|\/)(?:node_modules|vendor|\.git|\.next|dist|build|coverage|\.cache)(?:\/|$)/i.test(path))return false;return /\.(?:[cm]?[jt]sx?|json|ya?ml|sql|php|py|rb|go|rs|java|cs|html?|vue|svelte|toml|ini|conf|sh|pem|key|lock|prisma)$/i.test(path)||/(?:^|\/)(?:\.env(?:\.[\w.-]+)?|Dockerfile|\.npmrc|\.gitignore)$/i.test(path);}
export function analyzeSource(file:string,body:string,url:string,siteUrl?:string){
 const checks:AuditCheck[]=[],findings:Finding[]=[];const lines=body.split('\n'),code=/\.(?:[cm]?[jt]sx?|vue|svelte|html?|php|py|rb)$/i.test(file);
 function add(rule:string,title:string,status:CheckStatus,severity:Severity,line:number|undefined,evidence:string,fix:string,impact:string,basis:'indicator'|'configuration'='indicator'){
  const cleanFile=redact(file);const c:AuditCheck={id:rule+'|'+url,rule,category:rule.startsWith('repo.dependencies')||rule==='repo.json-valid'?'technical':'security',title,status,severity,weight:severity==='high'?4:severity==='medium'?2:1,url:redact(url),file:cleanFile,...(line?{line}:{}),evidence:redact(evidence).slice(0,600),recommendation:fix,security:{group:rule==='repo.secret'||rule==='repo.public-secret'?'secrets':rule.startsWith('repo.rls')?'api':'frontend',basis:status==='unavailable'?'not_tested':basis,method:'تحليل ثابت محلي للملف ضمن commit مثبت؛ لم يشغّل الكود ولا يثبت مسار بيانات كاملًا.',impact,fixSteps:[fix,'راجع السياق والاختبارات في بيئة منفصلة قبل نشر التغيير.'],verification:['راجع الملف والسطر في نفس commit، وتحقق من مصدر البيانات والصلاحيات.','أضف اختبارًا للسلوك الآمن ثم أعد الفحص.'],references:[]}};checks.push(c);
  if(status==='fail')findings.push({id:createHash('sha256').update(rule+'|'+file+'|'+url.replace(/\/blob\/[a-f\d]+\//,'/blob/')).digest('hex').slice(0,20),rule,category:c.category,severity,confidence:basis==='configuration'?'high':'medium',title:'راجع: '+title,description:impact,url:c.url,evidence:c.evidence,recommendation:fix,checks:c.security!.verification,file:cleanFile,...(line?{line}:{}),security:c.security});
 }
 const ast=supportsJavaScript(file)?analyzeJavaScript(file,body):undefined;
 const secrets=secretCount(body),secretLine=lines.findIndex(l=>secretCount(l)>0||/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(l));
 add('repo.secret','أنماط أسرار مرتفعة الصلاحية',secrets?'fail':'pass','high',secrets?Math.max(1,secretLine+1):undefined,`مطابقات مميزة: ${secrets}؛ القيم غير محفوظة ولم تختبر صلاحيتها.`,'عند تأكيد التعرض دوّر السر، وراجع سجلاته، وانقله للخادم واحذفه من الكود وسجل git.','قد يتيح سر صالح وصولًا غير مخول. المفتاح العام Supabase anon/publishable لا يعتبر سرًا إداريًا.');
 const rules:[string,string,RegExp,string,string,Severity][]=[
 ['repo.jwt-expiry','تجاهل انتهاء صلاحية JWT',/ignoreExpiration\s*:\s*true/,'تحقق من exp والساعة وهامش clockTolerance المحدود.','إعداد تجاهل انتهاء الصلاحية قد يقبل توكنات قديمة؛ راجع المكتبة ومسار المصادقة.','high'],
 ['repo.jwt-none','خوارزمية JWT غير موقعة',/algorithms\s*:\s*\[\s*['"]none/,'حدد خوارزميات التوقيع الموثوقة ومصدر المفاتيح.','قبول none قد يسمح بتوكن غير موقع؛ راجع سياق المكتبة.','high'],
 ['repo.cors-reflection','عكس Origin مع السماح بالاعتمادات',/origin\s*:\s*true/,'استخدم قائمة origins دقيقة عند credentials:true.','عكس Origin مع credentials:true يحتاج مراجعة؛ استغلاله يعتمد على المصادقة والكوكيز والسياق.','high'],
 ['repo.weak-hash','استخدام MD5 أو SHA1',/createHash\s*\(\s*['"](?:md5|sha1)/,'استخدم خوارزمية مناسبة للغرض؛ كلمات المرور تحتاج Argon2 أو scrypt أو bcrypt.','MD5/SHA1 غير مناسبين للسلامة الأمنية؛ قد يكون الاستخدام checksum غير أمني ومقصودًا.','medium'],
 ['repo.eval','تنفيذ نص ديناميكي',/\b(?:eval\s*\(|new\s+Function\s*\()/,'استبدل التنفيذ الديناميكي بمنطق محدد وقائمة عمليات مسموحة.','قد يتحول إدخال غير موثوق إلى تنفيذ كود؛ يلزم تتبع البيانات لتأكيد القابلية للاستغلال.','medium'],
 ['repo.html-sink','إدخال HTML مباشر',/dangerouslySetInnerHTML|\b(?:innerHTML|outerHTML)\s*=|\binsertAdjacentHTML\s*\(/,'استخدم textContent أو قوالب آمنة؛ نظف HTML غير الموثوق بمطهر مناسب.','قد يسمح موضع إدخال HTML بحقن سكريبت إذا وصلت بيانات غير موثوقة دون تنظيف.','medium'],
 ['repo.tls-bypass','تعطيل التحقق من TLS',/rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*(?:=|:)\s*["']?0/,'أبقِ التحقق من الشهادة مفعلًا وعالج الثقة والشهادات في الخادم.','قد يقبل الاتصال شهادات غير موثوقة؛ راجع ما إذا كان الإعداد يدخل بيئة الإنتاج.','high'],
 ['repo.sql-concat','استعلام SQL مبني ديناميكيًا',/\.(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*\b(?:SELECT|UPDATE|DELETE|INSERT)\b[^"']*["']\s*\+)/i,'استخدم معاملات مربوطة وواجهات استعلام آمنة؛ راجع المدخلات وقوائم الأسماء المسموحة.','بناء الاستعلام من مدخل غير موثوق قد يسبب SQL injection؛ النمط لا يثبت مصدر المدخل.','high'],
 ['repo.shell','إنشاء أمر نظام ديناميكي',/\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)/,'استخدم execFile/spawn بمعاملات منفصلة دون shell وحدد العمليات المسموحة.','قد يصبح إدخال غير موثوق جزءًا من أمر نظام؛ اسم الدالة وحده لا يثبت أنها child_process.','high'],
 ['repo.public-secret','إعداد سر في متغير واجهة عامة',/\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z\d_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD)[A-Z\d_]*\s*(?::|=)\s*["']?[^\s"';,]+/,'انقل الأسرار إلى متغيرات الخادم دون بادئة public، ودوّر ما نشر منها.','قد تدمج أدوات البناء المتغير في حزمة المتصفح؛ راجع القيمة والاستخدام الفعلي.','high']
 ];
 for(const [rule,title,pattern,fix,impact,severity]of rules){
  if(rule==='repo.html-sink'&&code&&!ast){add(rule,title,'unavailable',severity,undefined,'يتطلب تصنيف HTML الثابت أو المنظّف محلل JavaScript/TypeScript؛ لم يفترض ثغرة أو نجاحًا في هذه الصيغة.',fix,impact);continue;}
  if(!ast&&['repo.jwt-expiry','repo.jwt-none','repo.cors-reflection','repo.weak-hash'].includes(rule))continue;
  if(!code&&!['repo.tls-bypass','repo.public-secret'].includes(rule))continue;
  const lexical=ast&&rule==='repo.public-secret',astRule=ast&&!lexical;
  const line=lexical?(ast.publicSecrets.lines[0]??0)-1:astRule?(ast.matches[rule]?.[0]??0)-1:lines.findIndex(l=>pattern.test(l));
  const complete=lexical?ast.publicSecrets.complete:ast?.valid;
  const state=line>=0?'fail':ast&&!complete?'unavailable':ast&&!ast.hasCode?'not_applicable':'pass';
  const diagnostics=ast?.errors.map(e=>`TS${e.code} عند ${e.line}:${e.column}`).join('؛ ')??'';
  add(rule,title,state,severity,line>=0?line+1:undefined,state==='unavailable'?'تعذر إكمال تحليل هذا الملف؛ '+diagnostics+'؛ لم يفترض غياب النمط.':line>=0?(lexical?'إسناد مرصود في عقد AST، بما فيها العقد المستردة عند تعثر جزء آخر. راجع أخطاء الصياغة عند وجودها.':'نمط في عقدة AST أو قاعدة المصدر؛ لا يعرض محتوى السطر لحماية البيانات.'):'لم يرصد النمط ضمن الفحص المحدد؛ لا يثبت سلامة الملف بالكامل.',fix,impact);
  if(lexical&&checks.at(-1)?.security)checks.at(-1)!.security!.method='فحص عقد AST لإسنادات public، وفحص لغوي محافظ عند تعذر الصياغة؛ الالتباس لا يحسب نجاحًا. لا يتتبع كل مسارات نشر الأسرار.';
 }
 if(/\.json$/i.test(file)){let valid=true;try{JSON.parse(body);}catch{valid=false;}add('repo.json-valid','صياغة JSON قابلة للقراءة',valid?'pass':'fail','low',undefined,'فحص JSON.parse محلي؛ لا يثبت صحة كل إعداد في المخطط.','صحح صياغة الملف وراجع مخطط الإعدادات المناسب.','قد تؤدي صياغة غير صالحة إلى تجاهل الإعداد أو فشل التشغيل.','configuration');checks.at(-1)!.category='technical';}

 if(/(?:^|\/)package\.json$/.test(file)){try{const p=JSON.parse(body),deps={...p.dependencies,...p.devDependencies};const floating=Object.values(deps).filter(v=>typeof v==='string'&&/^(?:\*|latest|https?:|git\+)/.test(v)).length;add('repo.dependencies-pinned','اعتماديات بمراجع قابلة للضبط',floating?'fail':'pass','low',undefined,`اعتماديات بمراجع واسعة أو خارج سجل الحزم: ${floating}؛ لا قاعدة CVE محدثة.`,'راجع الإصدارات وثبت lockfile ومصادر الاعتماديات الموثوقة.','المراجع المتغيرة تقلل قابلية إعادة البناء؛ لا تثبت وجود إصدار مصاب.');}catch{add('repo.dependencies-json','قراءة package.json','fail','low',1,'JSON غير قابل للقراءة.','صحح package.json ثم أعد فحص الاعتماديات.','قد يفشل إعداد المشروع أو بناءه.','configuration');}}
 if(!code&&!/\.json$|\.sql$|(?:^|\/)package\.json$|\.env(?:\.|$)/i.test(file))add('repo.language-rules','قواعد اللغة المتخصصة','unavailable','low',undefined,'نُفذت قواعد الأسرار وإعدادات محدودة؛ لا محلل متخصص لهذه الصيغة.','استخدم محللًا متخصصًا للغة ضمن بيئة آمنة.','نجاح القواعد المشتركة لا يثبت فحص كل مخاطر هذه اللغة.');
 for(const c of checks)if(c.status==='unavailable')c.unavailableReason=ast&&!ast.valid?'collection_error':'unsupported';
 for(const c of checks)if(ast&&c.security&&c.rule!=='repo.secret'&&c.rule!=='repo.public-secret')c.security.method='تحليل عقد AST محلي باستخدام TypeScript؛ لا ينفذ الكود ولا يثبت تدفق بيانات كاملًا.';
 const extra=advancedSecurity(file,body,url);checks.push(...extra.checks);findings.push(...extra.findings);
 const discovery=siteUrl?discoverApiReferences(file,body,url,siteUrl):{services:[],checks:[],findings:[],excluded:0,limited:false};checks.push(...discovery.checks);findings.push(...discovery.findings);
 return {checks,findings,discovery};
}

export function repositoryScopeChecks(url:string):AuditCheck[]{return [
 {rule:'repo.runtime',title:'فحص التطبيق المنشور — HTTP',evidence:'يحتاج تفعيلًا بعد توثيق النطاق؛ اختبار API/RLS النشط خارج نطاق هذا المحرك.',group:'api' as const},
 {rule:'repo.dependencies-cve',title:'ثغرات الاعتماديات المعروفة CVE',evidence:'فعّل OSV في فحص جديد مع lockfile npm مدعوم؛ المعاينة الحالية لا تتصل بالخدمة.',group:'frontend' as const}
].map(item=>({id:item.rule+'|'+url,rule:item.rule,category:'security',status:'unavailable',unavailableReason:'configuration_required',weight:2,title:item.title,url,evidence:item.evidence,recommendation:'نفذ فحصًا مخولًا مستقلًا بأدوات محدثة وبيئة اختبار مناسبة.',security:{group:item.group,basis:'not_tested',method:'خارج نطاق التحليل الثابت المحلي المنفذ.',impact:'لا يمكن استنتاج سلامة هذا الجزء من نجاح قواعد الملفات.',fixSteps:['جهّز بيئة اختبار وأدوات مناسبة لهذا النوع من الفحص.'],verification:['سجل الأدلة الفعلية من الفحص المستقل قبل إصدار حكم.'],references:[]}}));}
