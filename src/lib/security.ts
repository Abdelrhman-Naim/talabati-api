import {load} from 'cheerio';
import {redact} from './redaction';
import {secretCount} from './secret-patterns';
import type {AuditCheck,CheckStatus,HttpPage,SecurityDetail,Severity} from './types';
const verification:Record<string,string>={
 'security.csp':'راجع CSP في Network وConsole؛ اختبر script-src وscript-src-attr وموارد التطبيق دون تعطيل الحماية.',
 'security.cookies':'افحص Set-Cookie في Network وخصائص كوكي الجلسة في Application؛ تأكد من تسجيل الدخول والخروج بعد تفعيل الأعلام.',
 'security.hsts':'تحقق أن استجابة HTTPS ترسل max-age موجبًا وأن كل النطاقات المراد تضمينها تدعم HTTPS.',
 'security.frame':'اختبر تضمين الصفحة من أصل غير مخول؛ راجع frame-ancestors الفعالة قبل الاعتماد على X-Frame-Options.',
 'security.secret':'بعد التدوير ابحث في الحزم المنشورة والسجل عن السر القديم، وراجع سجلات الاستخدام؛ لا تلصق قيم الأسرار في التقرير.',
 'security.password-form':'تحقق في بيئة اختبار أن كلمة المرور لا تظهر في عنوان URL أو سجلاته وأن طلب الإرسال POST إلى HTTPS.',
 'security.cors':'اختبر Origins موثوقة وغير موثوقة في بيئة مخولة؛ تحقق من سلوك المتصفح ومن رفض الطلبات غير المصرح بها على الخادم.',
 'security.active-mixed':'راجع Network وConsole للتأكد من زوال طلبات HTTP للمحتوى النشط وعدم ظهور أخطاء mixed content.',
 'security.sri':'تحقق أن hash يطابق الملف المنشور وأن المورد يعمل مع integrity وcrossorigin عند الحاجة.'
};
const mdn='https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/';
export function securityChecks(page:HttpPage):AuditCheck[]{
 const out:AuditCheck[]=[],h=page.headers,https=new URL(page.url).protocol==='https:',html=page.status>=200&&page.status<300&&/html/i.test(h['content-type']??'');
 const $=load(page.body);
 function add(rule:string,title:string,state:boolean|CheckStatus,evidence:string,fix:string,impact:string,group:SecurityDetail['group'],severity:Severity='low',doc=false,basis:SecurityDetail['basis']='configuration',reference=''){
  const status=doc&&!html?'unavailable':typeof state==='boolean'?(state?'pass':'fail'):state;
  out.push({id:rule+'|'+redact(page.url),rule,category:'security',title,status,url:redact(page.url),weight:severity==='high'?4:severity==='medium'?2:1,severity,evidence:doc&&!html?'لم تجمع صفحة HTML ناجحة؛ لم تنفذ هذه القاعدة.':redact(evidence).slice(0,1200),recommendation:fix,security:{group,basis:status==='unavailable'?'not_tested':basis,method:doc?'تحليل HTML والمصادر المجموعة؛ دون إرسال النماذج أو تنفيذ استغلال.':'تحليل الاستجابة المجموعة فقط؛ دون اختبار اختراق نشط.',impact,fixSteps:[fix,'طبّق التغيير في بيئة اختبار ثم تحقق من وظائف التطبيق قبل النشر.'],verification:[...(verification[rule]?[verification[rule]]:[]),'أعد الفحص على نفس المورد بعد نشر التغيير.','راجع استجابة الخادم وسلوك المتصفح الفعلي؛ نجاح القاعدة لا يثبت سلامة التطبيق.'],references:reference?[{label:'مرجع MDN',url:mdn+reference}]:[]}});
 }
 add('security.https','استخدام HTTPS',https,'بروتوكول المورد: '+new URL(page.url).protocol,'فعّل HTTPS وشهادة موثوقة وأعد توجيه HTTP.','النقل غير المشفر قد يسمح بقراءة البيانات أو تعديلها.','transport','medium');
 const policies=(h['content-security-policy']??'').split(/[\n,]/).filter(s=>s.trim()).map(policy=>{const dirs=new Map<string,string[]>();for(const part of policy.split(';')){const [name,...values]=part.trim().split(/\s+/);if(name&&!dirs.has(name.toLowerCase()))dirs.set(name.toLowerCase(),values);}return dirs;});
 const weaknesses=policies.map(p=>{
  const elem=p.get('script-src-elem')??p.get('script-src')??p.get('default-src');
  const evalSrc=p.get('script-src')??p.get('default-src');
  const attr=p.get('script-src-attr')??evalSrc;
  const attrTrusted=attr?.some(v=>/^'(?:nonce-[A-Za-z0-9+/_-]+=*|sha(?:256|384|512)-[A-Za-z0-9+/_-]+=*)'$/.test(v));
  const trusted=elem?.some(v=>/^'(?:nonce-[A-Za-z0-9+/_-]+=*|sha(?:256|384|512)-[A-Za-z0-9+/_-]+=*)'$/.test(v));
  const dynamic=trusted&&elem?.includes("'strict-dynamic'");
  return [!attr?'لا قيد على معالجات الأحداث inline':'',!evalSrc?'لا قيد على eval':'',attr?.includes("'unsafe-inline'")&&!attrTrusted?'يسمح معالجات أحداث inline غير مقيدة':'',!elem?'لا قيد على مصادر script':'',elem?.includes("'unsafe-inline'")&&!trusted&&!dynamic?'يسمح inline دون nonce/hash':'',!dynamic&&elem?.some(v=>['*','https:','http:','data:'].includes(v)||/^(?:https?:)?\/\/\*(?::[^/]+)?(?:\/.*)?$/.test(v)||/:\*(?:\/|$)/.test(v))?'مصادر سكريبت واسعة':'',evalSrc?.includes("'unsafe-eval'")?'يسمح unsafe-eval':''].filter(Boolean);
 });
 // Multiple enforced policies intersect. Do not infer a vulnerability from one permissive policy.
 const cspState=!policies.length?false:policies.length>1?'unavailable':weaknesses[0].length===0;
 add('security.csp','تحليل سياسة CSP المفروضة',cspState,!policies.length?'لا رأس CSP مفروض؛ Report-Only إن وجد لا يفرض الحماية.':policies.length>1?'سياسات متعددة متقاطعة؛ يلزم تحليل يدوي للسياسة الفعالة.':weaknesses[0].join('؛ ')||'لم يرصد هذا المحلل مصادر script الواسعة أو inline غير المقيد أو unsafe-eval. لا يثبت مقاومة XSS.','قيد script-src بمصادر لازمة أو nonce/hash، وأزل unsafe-eval بعد اختبار التوافق.','السياسة الضعيفة تقلل الدفاع الإضافي ضد حقن السكريبت؛ غيابها لا يثبت XSS.','headers','medium',false,'configuration','Content-Security-Policy');
 add('security.nosniff','منع تخمين MIME',h['x-content-type-options']?.trim().toLowerCase()==='nosniff','فحص قيمة X-Content-Type-Options دون محتوى الاستجابة.','أرسل X-Content-Type-Options: nosniff وContent-Type صحيحًا.','قد يفسر المتصفح موارد بنوع مختلف عن المقصود.','headers','low',false,'configuration','X-Content-Type-Options');
 const maxAge=(h['strict-transport-security']??'').match(/(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i);
 add('security.hsts','HSTS بمدة موجبة',https?Boolean(maxAge&&Number(maxAge[1])>0):'not_applicable',maxAge?'max-age='+maxAge[1]:'لا max-age صالحًا مرصودًا.','اضبط HSTS بمدة موجبة بعد التأكد من HTTPS؛ قيّم subdomains قبل تضمينها.','غياب HSTS يبقي زيارة HTTP الأولى دون ترقية محفوظة بواسطة هذا الرأس.','transport','low',false,'configuration','Strict-Transport-Security');
 const ancestor=policies.map(p=>p.get('frame-ancestors')).filter(Boolean) as string[][];
 const frame=ancestor.length?ancestor.some(a=>a.length>0&&!a.includes('*')&&a.every(v=>v==="'none'"||v==="'self'"||/^https?:\/\/[^*]+$/.test(v))):/^(DENY|SAMEORIGIN)$/i.test(h['x-frame-options']?.trim()??'');
 add('security.frame','سياسة تقييد تضمين الصفحة',frame,'فحص قيم X-Frame-Options وframe-ancestors؛ لا اختبار نقر فعلي.','حدد frame-ancestors بجهات موثوقة أو none؛ استخدم X-Frame-Options عند الحاجة.','قد يمكن تضمين الصفحة في إطار غير موثوق؛ قابلية clickjacking تحتاج تحقق السياق.','headers','low',false,'configuration','Content-Security-Policy/frame-ancestors');
 const ref=(h['referrer-policy']??'').split(',').map(x=>x.trim()).filter(x=>['no-referrer','no-referrer-when-downgrade','origin','origin-when-cross-origin','same-origin','strict-origin','strict-origin-when-cross-origin','unsafe-url'].includes(x)).at(-1);
 add('security.referrer','سياسة Referrer مقيدة صالحة',Boolean(ref&&ref!=='unsafe-url'&&ref!=='no-referrer-when-downgrade'),ref?'السياسة الفعالة: '+ref:'لا سياسة صالحة في الرأس؛ قد يطبق المتصفح سياسة افتراضية.','حدد strict-origin-when-cross-origin أو سياسة أشد تناسب التطبيق.','قد تنتقل معلومات المسار أو الاستعلام إلى جهات خارجية بحسب السياسة والمتصفح.','headers','low',false,'configuration','Referrer-Policy');
 const cookies=(h['set-cookie']??'').split(/\n|,(?=\s*[^\s;,=]+\s*=)/).filter(Boolean);const issues:string[]=[];
 for(const cookie of cookies){const [first,...parts]=cookie.split(';'),name=first.split('=')[0].trim(),attrs=new Map(parts.map(p=>{const i=p.indexOf('=');return [p.slice(0,i<0?undefined:i).trim().toLowerCase(),i<0?'':p.slice(i+1).trim()] as const;}));
  if(attrs.has('max-age')&&Number(attrs.get('max-age'))<=0)continue;
  if(!attrs.has('max-age')&&attrs.has('expires')&&Date.parse(attrs.get('expires')!)<=Date.now())continue;
  const errors:string[]=[];if(/session|auth|token|jwt|sid|connect\.sid/i.test(name)){if(!attrs.has('secure'))errors.push('Secure مفقود');if(!attrs.has('httponly'))errors.push('HttpOnly مفقود');}
  if(attrs.get('samesite')?.toLowerCase()==='none'&&!attrs.has('secure'))errors.push('SameSite=None يتطلب Secure');
  if(name.startsWith('__Secure-')&&!attrs.has('secure'))errors.push('بادئة __Secure- بلا Secure');
  if(name.startsWith('__Host-')&&(!attrs.has('secure')||attrs.has('domain')||attrs.get('path')!=='/'))errors.push('متطلبات __Host- غير مكتملة');
  if(errors.length)issues.push('كوكي #'+(cookies.indexOf(cookie)+1)+': '+errors.join('، '));
 }
 add('security.cookies','حماية الكوكيز المرصودة',cookies.length?issues.length===0:'not_applicable',`${cookies.length} رأس Set-Cookie؛ القيم والأسماء غير محفوظة. ${issues.join('؛ ')} لا يعتبر غياب SameSite وحده إثبات CSRF.`,'فعّل Secure وHttpOnly لكوكيز الجلسة، واضبط SameSite والبادئات حسب استخدامها.','كوكي جلسة بلا HttpOnly قد تقرأه السكريبتات؛ بلا Secure قد يرسله المتصفح على HTTP. تحديد الجلسة يعتمد نمط الاسم.','cookies','medium',false,'configuration','Set-Cookie');
 const cors=h['access-control-allow-origin'],credentials=h['access-control-allow-credentials']==='true';
 add('security.cors','اتساق رؤوس CORS',cors?!(cors.trim()==='*'&&credentials):'not_applicable',cors?.trim()==='*'&&credentials?'Wildcard مع credentials: المتصفح يمنع قراءة الاستجابة؛ لا يثبت تسرب بيانات.':cors?'لم يرصد تعارض wildcard/credentials؛ لم يختبر انعكاس Origin أو صلاحيات API.':'لا رأس CORS مرصود.','استخدم قائمة origins موثوقة عند تفعيل credentials؛ CORS لا يغني عن المصادقة.','الإعداد غير المتسق قد يعطل طلبات المتصفح. السماح الفعلي لجهة غير موثوقة يحتاج اختبارًا مخولًا مستقلًا.','api','low',false,'configuration','Access-Control-Allow-Origin');
 const secretSources=page.sourceBody&&page.sourceBody!==page.body?page.body+'\n'+page.sourceBody:page.body,n=secretCount(secretSources);
 add('security.secret','لا أنماط أسرار مرتفعة الصلاحية في المصادر',n===0,`أنماط مميزة محتملة: ${n}؛ القيم مخفية ولم تختبر صلاحيتها. المفتاح العام Supabase anon/publishable ومعرف AWS وحده لا يعتبران سرًا.`,'عند تأكيد التعرض ألغِ أو دوّر السر، وراجع السجلات وانقله إلى الخادم واحذفه من الحزم والسجل.','إذا كان السر صالحًا فقد يتيح وصولًا غير مصرح به؛ النمط وحده لا يثبت الصلاحية أو الاستغلال.','secrets','high',false,'indicator');
 let insecure=0,passwords=0;const baseAttr=$('base[href]').first().attr('href');let base=page.url;try{if(baseAttr)base=new URL(baseAttr,page.url).href;}catch{}
 $('form').each((_,el)=>{const f=$(el);if(!f.find('input[type="password"][name]:not([disabled])').length)return;passwords++;let action:URL;try{action=new URL(f.attr('action')||page.url,base);}catch{insecure++;return;}if((f.attr('method')??'get').toLowerCase()!=='post'||action.protocol!=='https:')insecure++;});
 add('security.password-form','إرسال كلمات المرور عبر HTTPS وPOST',passwords?insecure===0:'not_applicable',`نماذج بكلمات مرور مسماة: ${passwords}؛ وجهة أو طريقة غير آمنة: ${insecure}. قد تعترض JavaScript الإرسال؛ لم يرسل الفحص أي نموذج.`,'استخدم method=post ووجهة HTTPS؛ امنع وضع كلمات المرور في URL والسجلات.','الإرسال عبر GET قد يضع كلمة المرور في سجل المتصفح والخادم؛ HTTP قد يكشفها أثناء النقل.','frontend','high',true,'indicator');
 let mixed=0,external=0,noIntegrity=0;
 $('script[src],iframe[src],link[rel="stylesheet"][href]').each((_,el)=>{try{const u=new URL($(el).attr('src')??$(el).attr('href')??'',base);if(https&&u.protocol==='http:')mixed++;if(el.tagName==='script'&&u.origin!==new URL(page.url).origin&&u.protocol==='https:'){external++;if(!$(el).attr('integrity'))noIntegrity++;}}catch{}});
 add('security.active-mixed','لا مراجع محتوى نشط عبر HTTP',https?mixed===0:'not_applicable',`مراجع script/iframe/stylesheet عبر HTTP: ${mixed}؛ قد يحظرها المتصفح أو يرقيها؛ لم يثبت نقل غير مشفر.`,'استبدل مراجع المحتوى النشط بروابط HTTPS موثوقة.','قد تتعطل الموارد أو تنخفض حماية النقل إذا سمح تحميلها.','frontend','medium',true,'indicator');
 add('security.sri','إعلان SRI للسكريبتات الخارجية',external?noIntegrity===0:'not_applicable',`سكريبتات HTTPS خارجية: ${external}؛ بلا integrity: ${noIntegrity}؛ لا يثبت وجود الخاصية تطابق hash مع الملف. مؤشر مراجعة لسلسلة التوريد وليس إثبات اختراق.`,'أضف integrity وcrossorigin للموارد الثابتة المتوافقة أو استضف نسخة موثوقة محليًا.','التغيير غير المتوقع في سكريبت خارجي قد يؤثر على الصفحة؛ ليست كل الموارد الديناميكية مناسبة لـ SRI.','frontend','low',true,'indicator');

 return out;
}
