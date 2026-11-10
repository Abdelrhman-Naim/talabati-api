import {load} from 'cheerio';
import {redact} from './network';
import type {AuditCheck,Category,CheckStatus,HttpPage,Severity} from './types';

export {secretCount} from './secret-patterns';
import {securityChecks} from './security';
export function evaluateChecks(page:HttpPage):AuditCheck[]{
 const $=load(page.body);const out:AuditCheck[]=[];
 const usable=page.status>=200&&page.status<300&&(page.headers['content-type']??'').includes('html');
 const put=(rule:string,category:Category,title:string,state:boolean|CheckStatus,evidence:string,recommendation:string,weight=1,severity:Severity='low',document=true)=>{
  let status:CheckStatus=typeof state==='boolean'?(state?'pass':'fail'):state;
  if(document&&!usable){status='unavailable';evidence='لم تجمع صفحة HTML ناجحة؛ لا يمكن تقييم هذه القاعدة.';}
  out.push({id:rule+'|'+redact(page.url),rule,category,title,status,weight,url:redact(page.url),evidence:redact(evidence).slice(0,600),recommendation,severity});
 };
 const title=$('title').text().trim(),description=$('meta[name="description"]').attr('content')?.trim()??'';
 const canonical=$('link[rel="canonical"]').attr('href')??'';
 let canonicalValid=false;try{const u=new URL(canonical);canonicalValid=['http:','https:'].includes(u.protocol)&&!u.username&&!u.password;}catch{}
 const robots=[$('meta[name="robots"]').attr('content')??'',page.headers['x-robots-tag']??''].join(' ').toLowerCase();
 const headings=$('h1,h2,h3,h4,h5,h6').toArray().map(el=>Number(el.tagName.slice(1)));let ordered=true;for(let i=1;i<headings.length;i++)if(headings[i]>headings[i-1]+1)ordered=false;
 const clean=$('body').clone();clean.find('script,style,template,noscript').remove();const text=clean.text().replace(/\s+/g,' ').trim();
 const images=$('img'),missingAlt=$('img:not([alt])').length;let unnamed=0;
 const controls=$('input,select,textarea').toArray().filter(el=>!['hidden','submit','button','reset','image'].includes($(el).attr('type')??''));
 const labelled=(el:typeof controls[number])=>{
  const n=$(el),id=n.attr('id');const refs=(n.attr('aria-labelledby')??'').split(/\s+/).filter(Boolean);
  const refNames=refs.length>0&&refs.every(ref=>$('[id]').toArray().some(x=>$(x).attr('id')===ref&&$(x).text().trim()));
  return Boolean(n.attr('aria-label')?.trim()||refNames||(id&&$('label').toArray().some(l=>$(l).attr('for')===id&&$(l).text().trim()))||n.closest('label').text().trim());
 };
 for(const el of controls)if(!labelled(el))unnamed++;
 const buttons=$('button').toArray();const unnamedButtons=buttons.filter(el=>!$(el).text().trim()&&!labelled(el)&&!$(el).find('img[alt]').attr('alt')?.trim()).length;
 const ids=$('[id]').toArray().map(el=>$(el).attr('id')).filter(Boolean),duplicateIds=ids.length-new Set(ids).size;
 const schemas:Record<string,unknown>[]=[];const blocks=$('script[type="application/ld+json"]').toArray();let invalid=0;
 function addNodes(value:unknown,depth=0){if(depth>8||schemas.length>=100)return;if(Array.isArray(value)){for(const v of value.slice(0,100))addNodes(v,depth+1);return;}if(value&&typeof value==='object'){const n=value as Record<string,unknown>;schemas.push(n);if(n['@graph'])addNodes(n['@graph'],depth+1);}}
 for(const block of blocks){try{const value:unknown=JSON.parse($(block).text());if(!value||typeof value!=='object')invalid++;else addNodes(value);}catch{invalid++;}}
 const typed=schemas.some(s=>typeof s['@type']==='string'?Boolean(s['@type'].trim()):Array.isArray(s['@type'])&&s['@type'].some(t=>typeof t==='string'&&t.trim()));
 const identified=(value:unknown):boolean=>{if(typeof value==='string')return Boolean(value.trim());if(Array.isArray(value))return value.some(identified);if(value&&typeof value==='object'){const v=value as Record<string,unknown>;return [v.name,v.url,v['@id']].some(x=>typeof x==='string'&&x.trim());}return false;};
 const hasAuthor=Boolean($('meta[name="author"]').attr('content')?.trim()||schemas.some(s=>identified(s.author)||identified(s.publisher)));
 const dates=[$('meta[property="article:modified_time"]').attr('content'),$('meta[property="article:published_time"]').attr('content'),...$('time[datetime]').toArray().map(el=>$(el).attr('datetime')),...schemas.flatMap(s=>[s.dateModified,s.datePublished])];
 const hasDate=dates.some(d=>typeof d==='string'&&!Number.isNaN(Date.parse(d)));
 const viewport=$('meta[name="viewport"]').attr('content')??'';
 put('seo.title','seo','عنوان صفحة وصفي موجود',Boolean(title),`طول title: ${title.length} حرفًا`,'أضف title وصفيًا وفريدًا داخل head.',2,'medium');
 put('seo.title-unique','seo','عنوان واحد داخل المستند',$('title').length===1,`عناصر title: ${$('title').length}`,'استخدم عنصر title واحدًا مناسبًا.');
 put('seo.description','seo','وصف محركات البحث موجود',Boolean(description),`طول الوصف: ${description.length} حرفًا`,'أضف وصفًا يعبر عن محتوى الصفحة.');
 put('seo.canonical','seo','رابط canonical مطلق صالح',canonicalValid,canonical?'عثر على canonical؛ '+(canonicalValid?'عنوان HTTP(S) مطلق':'صيغة الرابط تحتاج مراجعة'):'لم يرصد canonical','راجع الرابط المرجعي واستخدم عنوانًا مطلقًا إذا احتاجته الصفحة.');
 put('seo.h1','seo','عنوان رئيسي واحد',$('h1').length===1,`عناصر h1: ${$('h1').length}`,'راجع بنية العناوين حسب الغرض من الصفحة.');
 put('seo.indexable','seo','لا يوجد توجيه noindex مرصود',!/(?:^|[\s,:])(?:noindex|none)(?:$|[\s,])/i.test(robots),'فحص meta robots وX-Robots-Tag فقط؛ ليس اختبار فهرسة فعلي.','إذا كان هدف الصفحة الفهرسة راجع noindex؛ قد يكون مقصودًا لصفحات خاصة.',2);
 put('seo.headings','seo','تدرج مستويات العناوين',headings.length?ordered:'not_applicable',`العناوين: ${headings.join(' ← ')||'لا توجد'}`,'تجنب القفز غير المبرر بين مستويات العناوين.');
 put('seo.og-title','seo','عنوان مشاركة Open Graph',Boolean($('meta[property="og:title"]').attr('content')),'فحص وجود og:title','أضف عنوان مشاركة مناسبًا؛ هذه قاعدة تحسين مشاركة محلية.');
 put('seo.og-description','seo','وصف مشاركة Open Graph',Boolean($('meta[property="og:description"]').attr('content')),'فحص وجود og:description','أضف وصف مشاركة يعكس المحتوى.');
 put('seo.rendered','seo','فهرسة المحتوى بعد تشغيل JavaScript','unavailable','لم يشغل متصفح أو يتصل Search Console.','يتطلب تدقيق rendered DOM وفهرسة مستقلة.');

 put('geo.structured-present','geo','بيانات منظمة قابلة للاكتشاف',blocks.length>0&&invalid===0&&typed,`كتل JSON-LD: ${blocks.length}؛ غير مقروءة: ${invalid}؛ نوع محدد: ${typed?'نعم':'لا'}`,'أضف بيانات منظمة قابلة للقراءة مناسبة للمحتوى؛ ليست شرطًا مضمونًا للظهور في AI.',2);
 put('geo.structured-valid','geo','JSON-LD مقروء ويحدد نوعًا',!blocks.length?'not_applicable':invalid===0&&typed,`كتل غير مقروءة: ${invalid}، وجود @type: ${typed?'نعم':'لا'}`,'صحح JSON وحدد @type مناسبًا. الفحص لا يثبت تطابق كل خصائص schema.org.',2);
 put('geo.author','geo','هوية كاتب أو ناشر معرفة',hasAuthor,'فحص meta author أو author/publisher في البيانات المنظمة','عرّف الجهة أو الكاتب عندما يلائم المحتوى.');
 put('geo.date','geo','تاريخ نشر أو تحديث قابل للقراءة',hasDate,'فحص time وarticle dates وحقول JSON-LD','أضف تاريخًا صحيحًا حيث يلائم نوع المحتوى؛ وجود التاريخ لا يثبت حداثة المعلومات.');
 put('geo.structure','geo','عنوان وأقسام واضحة',$('h1').length===1&&$('h2').length>0,`h1: ${$('h1').length}، h2: ${$('h2').length}`,'قسّم المحتوى إلى أقسام مفهومة وعناوين واضحة.');
 put('geo.content','geo','قدر كافٍ من النص القابل للاستخراج',text.length>=600,`نص HTML بعد حذف السكريبتات: ${text.length} حرفًا؛ عتبة محلية 600`,'راجع وضوح الإجابة وكفاية المحتوى بحسب الصفحة. طول النص مؤشر محلي لا عامل ترتيب مضمون.');

 put('a11y.lang','accessibility','لغة HTML محددة',Boolean($('html').attr('lang')?.trim()),'فحص html[lang]','حدد لغة المستند الصحيحة.',2,'medium');
 put('a11y.image-alt','accessibility','خاصية alt للصور',images.length?missingAlt===0:'not_applicable',`${images.length} صور؛ ${missingAlt} دون alt`,'أضف alt وصفيًا للمعلوماتية وفارغًا للزخرفية.',2,'medium');
 put('a11y.input-name','accessibility','أسماء لحقول الإدخال',controls.length?unnamed===0:'not_applicable',`${controls.length} حقول؛ ${unnamed} بلا اسم مرصود`,'اربط label بالحقل أو استخدم اسم وصول مناسبًا.',2,'medium');
 put('a11y.button-name','accessibility','أسماء للأزرار',buttons.length?unnamedButtons===0:'not_applicable',`${buttons.length} أزرار؛ ${unnamedButtons} بلا اسم مرصود`,'عرّف وظيفة الأزرار بالاسم أو النص.',2,'medium');
 put('a11y.ids','accessibility','معرفات عناصر غير مكررة',duplicateIds===0,`معرفات مكررة: ${duplicateIds}`,'اجعل IDs فريدة لضمان صحة الربط.');
 put('a11y.main','accessibility','منطقة محتوى رئيسية معرفة',$('main,[role="main"]').length>0,'فحص main أو role=main','استخدم landmark مناسبًا للمحتوى الأساسي.');
 put('a11y.contrast','accessibility','تباين الألوان الفعلي','unavailable','لم تحسب الألوان بعد تطبيق CSS.','يتطلب محرك وصول ومتصفح.');
 put('a11y.keyboard','accessibility','رحلات لوحة المفاتيح','unavailable','لم تنفذ تفاعلات مستخدم.','يتطلب تشغيل رحلة بلوحة المفاتيح.');

 put('ux.viewport','ux','إعداد عرض الجوال موجود',Boolean(viewport),'فحص meta viewport','أضف viewport مناسبًا واختبر أحجام الشاشات.',2,'medium');
 put('ux.zoom','ux','لا يوجد منع تكبير مرصود',viewport?!/user-scalable\s*=\s*no|maximum-scale\s*=\s*1(?:\.0)?(?:\s|,|$)/i.test(viewport):'not_applicable','فحص قيود user-scalable وmaximum-scale في viewport','اسمح للمستخدم بتكبير المحتوى.');
 put('ux.direction','ux','اتجاه المستند العربي محدد',/^ar(?:-|$)/i.test($('html').attr('lang')??'')?$('html').attr('dir')==='rtl':'not_applicable','فحص dir=rtl عند تعريف لغة عربية','اضبط الاتجاه المناسب للمستند العربي.');
 put('ux.navigation','ux','منطقة تنقل دلالية',$('nav,[role="navigation"]').length>0,'فحص nav أو role=navigation','عرّف منطقة التنقل دلاليًا حيث تناسب الصفحة.');
 put('ux.visual','ux','التمدد الأفقي عند عرض الصفحة','unavailable','لم تتوفر قياسات DOM من المتصفح؛ لا يعتمد هذا الفحص على صور أو نموذج رؤية.','فعّل Chromium لقياس أبعاد الصفحة آليًا.');

 put('technical.http','technical','استجابة HTTP ناجحة',page.status>=200&&page.status<300,`HTTP ${page.status}`,'راجع المسار والخادم وحالة الاستجابة.',2,'high',false);
 put('technical.html','technical','محتوى HTML متاح',(page.headers['content-type']??'').includes('html'),`Content-Type: ${page.headers['content-type']??'غير محدد'}`,'قدم HTML صحيحًا للمسار المفحوص.',1,'medium',false);
 put('technical.doctype','technical','تعريف HTML5 doctype',/^\s*<!doctype html/i.test(page.body),'فحص doctype في أول المستند','أضف <!doctype html> لتجنب quirks mode.');
 const mixed=$('[src]').toArray().filter(el=>/^http:\/\//i.test($(el).attr('src')??'')).length;
 put('technical.mixed','technical','لا موارد HTTP صريحة داخل HTTPS',page.url.startsWith('https:')?mixed===0:'not_applicable',`موارد src تبدأ HTTP: ${mixed}`,'انقل الموارد إلى HTTPS؛ لم تنفذ requests ديناميكية.',2);
 put('technical.console','technical','أخطاء console وقت التشغيل','unavailable','لم ينفذ JavaScript الموقع.','يتطلب متصفحًا لتسجيل أخطاء التنفيذ.');

 out.push(...securityChecks(page));

 const measuredTime=page.elapsedMs>0&&Number.isFinite(page.elapsedMs),measuredBytes=page.bytes>=0&&Number.isFinite(page.bytes);
 put('performance.response','performance','زمن جلب HTTP ضمن 1500ms',measuredTime?page.elapsedMs<=1500:'unavailable',measuredTime?`${page.elapsedMs} ms لجلب الاستجابة كاملة؛ عتبة محلية`:'زمن الجلب غير مقاس','راجع زمن الخادم والنقل؛ هذا ليس LCP أو TTFB.',1,'low');
 put('performance.payload','performance','حجم HTML ضمن 250KiB',measuredBytes?page.bytes<=250*1024:'unavailable',measuredBytes?`${page.bytes} bytes؛ الجسم المستلم فقط`:'حجم الجسم غير مقاس','قلل HTML غير الضروري؛ لا يشمل الحجم كل موارد الصفحة.',1,'low');
 put('performance.lcp','performance','LCP من المتصفح','unavailable','لم يشغل Lighthouse.','يتطلب محرك أداء فعليًا.',1,'low',false);
 put('performance.cls','performance','CLS من المتصفح','unavailable','لا قياس لتغير التخطيط.','يتطلب محرك أداء فعليًا.',1,'low',false);
 put('performance.inp','performance','INP ميداني','unavailable','لا بيانات مستخدمين حقيقية.','اربط بيانات ميدانية موثوقة.',1,'low',false);
 if(page.browser){
  const b=page.browser;
  const update=(rule:string,status:CheckStatus,evidence:string,title?:string)=>{const c=out.find(c=>c.rule===rule);if(c){c.status=status;c.evidence=redact(evidence).slice(0,600);if(title)c.title=title;}};
  update('seo.rendered',usable?'pass':'unavailable','تحليل DOM بعد تشغيل JavaScript وانتظار الشبكة ضمن النافذة المحددة.','المحتوى المعروض بعد تشغيل JavaScript');
  update('technical.console',b.consoleErrors.length?'fail':'pass',b.consoleErrors.length?b.consoleErrors.join(' | '):'لم يرصد pageerror ضمن نافذة الفحص. قد يسبب حظر طلبات الكتابة أخطاء في هذه البيئة.','أخطاء JavaScript في بيئة الفحص');
  update('ux.visual',b.overflow?'fail':'pass',`فحص التمدد الأفقي عند viewport=${b.viewport}؛ ليس تحليلًا بصريًا كاملًا.`,'لا تمدد أفقي عند عرض الفحص');
  const lcp=usable&&typeof b.lcp==='number'&&Number.isFinite(b.lcp)&&b.lcp>0;
  update('performance.lcp',lcp?(b.lcp!<=2500?'pass':'fail'):'unavailable',lcp?`LCP مختبري: ${Math.round(b.lcp!)}ms؛ نافذة ${b.observedMs}ms؛ ${b.viewport}`:'لم يسجل عنصر LCP صالح؛ لا يتم افتراض الصفر.','LCP مختبري ضمن 2500ms');
  const cls=usable&&typeof b.cls==='number'&&Number.isFinite(b.cls)&&b.cls>=0;
  update('performance.cls',cls?(b.cls!<=0.1?'pass':'fail'):'unavailable',cls?`CLS مختبري: ${b.cls!.toFixed(3)}؛ نافذة ${b.observedMs}ms؛ ${b.viewport}`:'لم يتوفر مراقب تغير التخطيط.','CLS مختبري ضمن 0.1');
  const contrast=b.checks.find(c=>c.rule==='axe.color-contrast');if(contrast)update('a11y.contrast',contrast.status,contrast.evidence,'تباين الألوان عبر axe');
  out.push(...b.checks);
 }
 return [...new Map(out.map(c=>[c.rule==='security.api-discovery'||c.rule==='security.api-reference-https'?c.id:c.rule+'|'+c.url,c])).values()];
}
