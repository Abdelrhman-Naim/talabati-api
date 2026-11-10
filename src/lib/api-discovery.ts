import ts from 'typescript';
import {createHash} from 'node:crypto';
import {validateTarget,redact} from './network';
import type {Service,AuditCheck,Finding} from './types';
const apiName=(name:string)=>/(?:api[_-]?(?:url|origin|endpoint)|supabase[_-]?(?:url|origin)|base[_-]?url|endpoint)/i.test(name);
export function mergeApiServices(target:Service[],incoming:Service[],cap=64){let limited=false;for(const service of incoming){const prior=target.find(s=>s.origin===service.origin);if(prior){if(/API|Supabase/i.test(service.type)&&!/API|Supabase/i.test(prior.type))prior.type=service.type;for(const path of service.paths)if(!prior.paths.includes(path)){if(prior.paths.length<20)prior.paths.push(path);else limited=true;}if(prior.status!=='observed_request'&&service.status==='observed_request')prior.status='observed_request';}else if(target.length<cap)target.push({...service,paths:service.paths.slice(0,20)});else limited=true;}return limited;}
export function apiReferenceResults(services:Service[],source:string,file?:string,line=1){
 const checks:AuditCheck[]=[],findings:Finding[]=[];
 for(const service of services){const id=createHash('sha256').update(service.origin+'|'+source+'|'+line).digest('hex').slice(0,18),secure=service.origin.startsWith('https:');
  checks.push({id:'api-discovery|'+id,rule:'security.api-discovery',category:'technical',status:'pass',weight:1,title:'اكتشاف مرجع API تلقائيًا',url:redact(source),file:file?redact(file):undefined,line,evidence:`أصل: ${service.origin}؛ النوع: ${service.type}؛ المسارات: ${service.paths.join('، ')}. ${service.status==='observed_request'?'رُصد طلب للمتصفح؛ ليس اختبار صلاحيات.':'مرجع من المصدر؛ لم يرسل طلب إلى الخدمة.'}`,recommendation:'راجع المصدر والمسارات. لا يحتاج الاكتشاف إدخال رابط API أو مفاتيحه يدويًا.'});
  const c:AuditCheck={id:'api-https|'+id,rule:'security.api-reference-https',category:'security',status:secure?'pass':'fail',weight:2,title:'HTTPS في مرجع API المكتشف',url:redact(source),file:file?redact(file):undefined,line,severity:'medium',evidence:`أصل API المشار إليه: ${service.origin}. ${secure?'المرجع يستخدم HTTPS؛ لم تفحص الشهادة أو إعداد TLS للخدمة.':'المرجع يستخدم HTTP غير مشفر؛ قد يكون إعداد تطوير، ولم يثبت إرساله في الإنتاج.'}`,recommendation:'استخدم HTTPS في الإنتاج وتحقق من الوجهة المنشورة.',security:{group:'api',basis:'indicator',method:'اكتشاف محلي من الكود/الاستجابات المجموعة وطلبات المتصفح المرصودة؛ بلا طلبات إضافية للخدمة.',impact:'مراجع HTTP قد تعرض بيانات النقل إذا استُخدمت؛ اكتشاف الخدمة لا يثبت تفويضها أو حالة RLS.',fixSteps:['راجع عنوان API في إعداد الإنتاج واستخدم HTTPS.'],verification:['أعد الفحص وراجع طلبات المتصفح في بيئة الاختبار.'],references:[]}};checks.push(c);
  if(!secure)findings.push({id:c.id,rule:c.rule,category:'security',severity:'medium',confidence:'medium',title:c.title,description:c.security!.impact,url:c.url,evidence:c.evidence,recommendation:c.recommendation,file:c.file,line,checks:c.security!.verification,security:c.security});
 }
 return {checks,findings};
}
export function discoverApiReferences(file:string,body:string,source:string,siteUrl:string){
 const services:Service[]=[],checks:AuditCheck[]=[],findings:Finding[]=[];let excluded=0,limited=false,count=0;if(body.length>524288){body=body.slice(0,524288);limited=true;}
 const site=new URL(siteUrl),add=(value:string,line:number,type='API من المصدر')=>{
  if(++count>100){limited=true;return;}
  if(!/^(?:https?:\/\/|\/[^/])/.test(value))return;
  try{const candidate=new URL(value,site);if(candidate.username||candidate.password){excluded++;return;}candidate.search='';candidate.hash='';const u=validateTarget(candidate.href);if(!/^https?:$/.test(u.protocol))return;
   let path=u.pathname;try{path=decodeURIComponent(path);}catch{}
   if(redact(path)!==path){excluded++;return;}
   const service:Service={origin:u.origin,type:u.hostname.endsWith('.supabase.co')?'Supabase':type,source:redact(source),status:'observed_reference',paths:[path.slice(0,200)]};
   const fresh=!services.some(s=>s.origin===service.origin);limited=mergeApiServices(services,[service],20)||limited;
   if(fresh&&services.some(s=>s.origin===service.origin)){const out=apiReferenceResults([service],source,file,line);checks.push(...out.checks);findings.push(...out.findings);}
  }catch{excluded++;}
 };
 // Configuration readers recognize API-related keys only; never persist keys/values containing credentials.
 if(/(?:^|\/)\.env(?:\.|$)|\.(?:toml|ya?ml|ini)$/i.test(file)){
  for(const [i,line]of body.split('\n').entries()){const match=line.match(/^\s*(?:export\s+)?([A-Za-z_][\w.-]*)\s*[=:]\s*["']?(https?:\/\/[^\s"'#]+)["']?\s*(?:#.*)?$/);if(match&&apiName(match[1]))add(match[2],i+1);}
 }else if(/\.json$/i.test(file)){
  try{JSON.parse(body);const tree=ts.createSourceFile('config.ts','const __config = '+body,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);let visited=0;const visit=(node:ts.Node)=>{if(++visited>10000){limited=true;return;}if(ts.isPropertyAssignment(node)){const key=ts.isIdentifier(node.name)||ts.isStringLiteral(node.name)?node.name.text:'';if(apiName(key)&&ts.isStringLiteral(node.initializer))add(node.initializer.text,tree.getLineAndCharacterOfPosition(node.name.getStart(tree)).line+1);}ts.forEachChild(node,visit);};visit(tree);}catch{}

 }else if(/\.(?:[cm]?[jt]sx?|vue|svelte|html?)$/i.test(file)){
  const chunks:{text:string;offset:number}[]=[];
  if(/\.(?:vue|svelte|html?)$/i.test(file)){for(const m of body.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)){if(/\btype\s*=\s*["']application\/ld\+json/.test(m[1]))continue;chunks.push({text:m[2],offset:body.slice(0,m.index!+m[0].indexOf('>')+1).split('\n').length-1});}}else chunks.push({text:body,offset:0});
  for(const chunk of chunks){const tree=ts.createSourceFile(file,chunk.text,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX),line=(n:ts.Node)=>chunk.offset+tree.getLineAndCharacterOfPosition(n.getStart(tree)).line+1;
   const literal=(n:ts.Node|undefined)=>n&&(ts.isStringLiteral(n)||ts.isNoSubstitutionTemplateLiteral(n))?n.text:undefined;
   const member=(n:ts.Node)=>ts.isIdentifier(n)?n.text:ts.isPropertyAccessExpression(n)?n.name.text:'';
   function visit(n:ts.Node){
    if(ts.isStringLiteralLike(n)&&/^https?:\/\/[^/?#]+\.supabase\.co(?:[/?#]|$)/i.test(n.text))add(n.text,line(n),'Supabase');
    if(ts.isVariableDeclaration(n)&&ts.isIdentifier(n.name)&&apiName(n.name.text)){const value=literal(n.initializer);if(value)add(value,line(n));}
    if(ts.isPropertyAssignment(n)){const name=ts.isIdentifier(n.name)||ts.isStringLiteral(n.name)?n.name.text:'';if(apiName(name)){const value=literal(n.initializer);if(value)add(value,line(n));}}
    if(ts.isCallExpression(n)){
     const method=member(n.expression),apiCall=['fetch','axios','createClient'].includes(method)||ts.isPropertyAccessExpression(n.expression)&&['get','post','put','patch','delete','head','request'].includes(method)&&ts.isIdentifier(n.expression.expression)&&n.expression.expression.text==='axios';
     if(apiCall){const value=literal(n.arguments[0]);if(value)add(value,line(n),method==='createClient'?'عميل API / Supabase':'API من استدعاء الكود');}
    }
    ts.forEachChild(n,visit);
   }visit(tree);
  }
 }
 for(const c of checks)if(c.rule==='security.api-discovery'){const origin=services.find(s=>c.evidence.startsWith('أصل: '+s.origin+'؛'));if(origin)c.evidence=`أصل: ${origin.origin}؛ النوع: ${origin.type}؛ المسارات: ${origin.paths.join('، ')}. مرجع من المصدر؛ لم يرسل طلب إلى الخدمة.`;}
 return {services,checks,findings,excluded,limited};
}
