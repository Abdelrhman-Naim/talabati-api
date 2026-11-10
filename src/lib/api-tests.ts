import {z} from 'zod';
import {validateTarget,requestResource,redact} from './network';
import {secretCount} from './secret-patterns';
import type {Store} from './db';
import type {Scan,AuditCheck,Finding} from './types';
export const apiConfigSchema=z.object({origin:z.string().max(300),proofPath:z.string().max(1000),kind:z.enum(['api','supabase','storage']),tokenA:z.string().min(8).max(4096),tokenB:z.string().min(8).max(4096),publicKey:z.string().max(1024).default(''),pathA:z.string().max(1500),pathB:z.string().max(1500),markerA:z.string().regex(/^aegis-test-[a-zA-Z0-9_-]{4,80}$/),markerB:z.string().regex(/^aegis-test-[a-zA-Z0-9_-]{4,80}$/),staging:z.literal(true)});
export type ApiConfigInput=z.infer<typeof apiConfigSchema>;
export type ApiConfigInfo={id:string;projectId:string;origin:string;kind:ApiConfigInput['kind'];proofPath:string;verifiedUntil:number;updatedAt:number};
export type ApiTransport=typeof requestResource;
export function parseApiConfig(raw:unknown):ApiConfigInput{
 const c=apiConfigSchema.parse(raw),origin=validateTarget(c.origin);
 if(origin.protocol!=='https:'||origin.href!==origin.origin+'/')throw new Error('استخدم أصل HTTPS فقط بلا مسار أو query');
 c.origin=origin.origin;
 for(const path of [c.pathA,c.pathB,c.proofPath]){
  if(!path.startsWith('/')||path.startsWith('//')||/[\\\r\n#]/.test(path)||/%(?:2f|5c|2e)/i.test(path))throw new Error('مسار اختبار غير صالح');
  let decoded=path;for(let i=0;i<5;i++){try{const next=decodeURIComponent(decoded);if(next===decoded)break;decoded=next;}catch{throw new Error('ترميز المسار غير صالح');}}
  if([c.tokenA,c.tokenB,c.publicKey,c.markerA,c.markerB].filter(Boolean).some(value=>decoded.includes(value)))throw new Error('احذف الاعتمادات وعلامات الاختبار من المسارات؛ تحفظ في حقولها فقط');
  const u=validateTarget(c.origin+path);if(u.origin!==c.origin)throw new Error('مسار خارج أصل API');
  if(/(?:^|\/)(?:rpc|auth|logout|delete|remove|reset|revoke|destroy|signout|sign-out|admin)(?:\/|$)/i.test(u.pathname))throw new Error('استخدم مسار قراءة مورد تجريبي فقط؛ نقاط الإجراءات غير مسموحة');
 }
 if(c.pathA===c.pathB||c.markerA===c.markerB||c.tokenA===c.tokenB)throw new Error('استخدم حسابين وموردين وعلامتين مختلفين');
 for(const token of [c.tokenA,c.tokenB,c.publicKey])if(/[\r\n\s]/.test(token)||secretCount(token)||/service_role|sb_secret_/i.test(token))throw new Error('استخدم access tokens لحسابَي اختبار منخفضَي الصلاحية ومفتاح API عام فقط');
 if(c.publicKey&&!/^sb_publishable_[a-zA-Z0-9_-]+$/.test(c.publicKey)){
  let anon=false;try{const claims=JSON.parse(Buffer.from(c.publicKey.split('.')[1],'base64url').toString('utf8'));anon=c.publicKey.split('.').length===3&&claims.role==='anon'&&!claims.sub;}catch{}
  if(!anon)throw new Error('المفتاح العام يجب أن يكون Supabase publishable أو JWT بدور anon؛ لا تستخدم توكن مستخدم للزائر');
 }
 const subject=(token:string)=>{try{const claims=JSON.parse(Buffer.from(token.split('.')[1],'base64url').toString('utf8'));return typeof claims.sub==='string'&&claims.sub?claims.sub:null;}catch{return null;}};
 if(subject(c.tokenA)&&subject(c.tokenA)===subject(c.tokenB))throw new Error('التوكنان يمثلان نفس المستخدم؛ استخدم هويتين مختلفتين');
 if(c.kind!=='api'&&!c.publicKey)throw new Error('Supabase يحتاج مفتاح publishable/anon عامًا');
 return c;
}
export async function verifyApiConfig(store:Store,owner:string,projectId:string,signal?:AbortSignal,transport:ApiTransport=requestResource){
 const config=store.apiConfig(owner,projectId),project=store.ownedProject(owner,projectId);if(!config||!project)throw new Error('احفظ إعداد API أولًا');
 const page=await transport(config.origin+config.proofPath,{origin:config.origin,maxResponseBytes:4096,signal:signal?AbortSignal.any([signal,AbortSignal.timeout(10000)]):AbortSignal.timeout(10000)});
 if(page.url!==config.origin+config.proofPath||page.status!==200||page.body.trim()!==project.token)throw new Error('لم يطابق ملف إثبات ملكية API؛ لا إعادة توجيه مسموحة');
 store.verifyApiConfig(owner,projectId,config.id);return store.apiConfig(owner,projectId);
}
function hasMarker(body:string,marker:string){try{const data=JSON.parse(body);let count=0;const find=(v:unknown,depth=0):boolean=>{if(++count>2000||depth>12)return false;if(typeof v==='string')return v===marker;if(Array.isArray(v))return v.some(x=>find(x,depth+1));return !!v&&typeof v==='object'&&Object.values(v).some(x=>find(x,depth+1));};return find(data);}catch{return body.trim()===marker;}}
function emptyRows(body:string){try{const data=JSON.parse(body);return Array.isArray(data)&&data.length===0;}catch{return false;}}
export async function runApiTests(store:Store,job:Scan,signal?:AbortSignal,transport:ApiTransport=requestResource,onCheck?:(check:AuditCheck)=>void){
 const checks:AuditCheck[]=[],findings:Finding[]=[];
 const info=store.apiConfig(job.owner_id,job.project_id);
 const allowed=()=>{const live=store.apiConfig(job.owner_id,job.project_id);return Boolean(job.apiTests&&live&&live.id===job.apiConfigId&&live.verifiedUntil>Date.now()&&store.isRunning(job.id)&&!signal?.aborted);};
 let config:ApiConfigInput|undefined;if(allowed())try{config=store.apiConfigSecret(job.owner_id,job.project_id,job.apiConfigId!);}catch{}
 const scope='اختبار قراءة موردين تجريبيين فقط؛ لا يثبت كل سياسات RLS أو الكتابة أو كل نقاط API.';
 const baselines:Record<string,boolean>={A:false,B:false};
 const plan=[['A',0,'A'],['B',1,'B'],['A',0,'B'],['A',0,'anonymous'],['B',1,'A'],['B',1,'anonymous']] as const;
 for(const [owner,index,identity] of plan){
   const isOwner=identity===owner,rule=isOwner?'security.api-baseline':config?.kind==='api'||info?.kind==='api'?'security.api-auth':'security.supabase-rls';
   const c:AuditCheck={id:`api-matrix|${index}|${identity}`,rule,category:'security',weight:isOwner?1:4,status:'unavailable',unavailableReason:'configuration_required',title:`مورد ${owner} — ${isOwner?'وصول المالك':identity==='anonymous'?'منع الزائر':'عزل الحساب الآخر'}`,url:info?.origin??'',evidence:'لم يفعّل اختبار API لهذه المهمة أو يلزم إعداد موثق حديث.',recommendation:'من صفحة GitHub وAPI، جهّز حسابين وموردين تجريبيين ووثّق أصل API ثم فعّل مصفوفة القراءة في الفحص العميق.',execution:{state:'completed',engine:'api-read-matrix/0.9',method:'GET',identity,resource:owner,expected:isOwner?'HTTP 200 مع علامة المورد التجريبي':config?.kind==='storage'||info?.kind==='storage'?'رفض 401/403/404 دون علامة المورد':'رفض 401/403/404 أو JSON [] دون علامة المورد',observed:'لم يرسل طلب',attempted:false,at:Date.now()}};
   if(job.apiTests&&!config){c.evidence='الإعداد الموثق غير متاح أو تغير أو انتهت صلاحيته/حجز المهمة؛ لم يرسل طلب.';}
   if(config&&allowed()){
    if(!isOwner&&(!baselines[owner]||identity!=='anonymous'&&!baselines[identity])){c.unavailableReason='collection_error';c.evidence='لم يثبت وصول صاحب المورد؛ أُلغي اختبار الرفض لتجنب نجاح وهمي.';}
    else{
     const path=owner==='A'?config.pathA:config.pathB,marker=owner==='A'?config.markerA:config.markerB;
     const headers:Record<string,string>={accept:config.kind==='storage'?'text/plain':'application/json','cache-control':'no-cache'};
     if(config.publicKey)headers.apikey=config.publicKey;
     if(identity!=='anonymous')headers.authorization='Bearer '+(identity==='A'?config.tokenA:config.tokenB);
     else if(config.publicKey.split('.').length===3)headers.authorization='Bearer '+config.publicKey;
     c.url=config.origin+path;c.execution!.attempted=true;c.execution!.state='planned';c.execution!.observed='طلب GET جارٍ؛ بانتظار الاستجابة';c.evidence='بدأ إرسال الطلب؛ لم تحسم النتيجة بعد.';c.security={group:'api',basis:'not_tested',method:'GET لمورد تجريبي مصرح به',impact:scope,fixSteps:[c.recommendation],verification:['انتظار اكتمال الاستجابة'],references:[]};onCheck?.(c);
     try{
      const requestSignal=signal?AbortSignal.any([signal,AbortSignal.timeout(10000)]):AbortSignal.timeout(10000);
      const controller=new AbortController(),watch=setInterval(()=>{if(!allowed())controller.abort();},50);
      let page:Awaited<ReturnType<ApiTransport>>;try{page=await transport(c.url,{origin:config.origin,method:'GET',headers,maxResponseBytes:65536,signal:AbortSignal.any([requestSignal,controller.signal])});}finally{clearInterval(watch);controller.abort();}
      if(!allowed())throw new Error('revoked');
      const markerSeen=hasMarker(page.body,marker),unexpectedUrl=page.url!==c.url;
      c.execution!.httpStatus=page.status;c.execution!.elapsedMs=page.elapsedMs;c.execution!.bytes=page.bytes;c.execution!.observed=`HTTP ${page.status}؛ ${page.bytes} بايت؛ علامة المورد ${markerSeen?'موجودة':'غير موجودة'}`;
      if(unexpectedUrl||page.status>=300&&page.status<400){c.evidence='إعادة توجيه/وجهة غير مطابقة؛ لم تتبع ولم تعتبر رفضًا ناجحًا.';c.unavailableReason='collection_error';}
      else if(isOwner){baselines[owner]=page.status===200&&markerSeen;if(baselines[owner]){c.status='pass';c.evidence='أثبت حساب المالك قراءة المورد التجريبي المحدد.';}else {c.unavailableReason='collection_error';c.evidence='لم تثبت استجابة HTTP 200 مع العلامة الصحيحة؛ قد تكون الاعتمادات منتهية أو المورد غير جاهز.';}}
      else if(markerSeen&&page.status>=200&&page.status<300){c.status='fail';c.severity='high';c.evidence='أعادت الاستجابة علامة المورد التجريبي لحساب غير مالك أو زائر؛ ثبت كشف المورد المحدد.';}
      else if(!markerSeen&&([401,403,404].includes(page.status)||config.kind!=='storage'&&page.status===200&&emptyRows(page.body))){c.status='pass';c.evidence='ثبت منع قراءة المورد المحدد لهذا الدور بعد نجاح وصول مالكه.';}
      else {c.unavailableReason='collection_error';c.evidence='استجابة غير حاسمة؛ ليست رفضًا معروفًا ولا كشفًا مثبتًا. راجع شكل الاستجابة.';}
      c.recommendation=c.status==='fail'?'أصلح تفويض القراءة أو سياسة RLS/Storage لهذا المورد ثم أعد المصفوفة.':scope;
      if(c.status!=='unavailable')delete c.unavailableReason;
     }catch{c.unavailableReason='collection_error';c.evidence='تعذر إكمال الطلب أو انتهى التوثيق/حجز العامل؛ لا نجاح محتسب.';c.execution!.observed='لا استجابة موثوقة مكتملة';}
    }
   }
   c.execution!.state=store.isRunning(job.id)?'completed':job.apiTests?'cancelled':'completed';
   c.url=redact(c.url);
   if(config)for(const secret of [config.tokenA,config.tokenB,config.publicKey,config.markerA,config.markerB].filter(Boolean))c.url=c.url.split(secret).join('[hidden]').split(encodeURIComponent(secret)).join('[hidden]');
   c.security={group:'api',basis:c.status==='unavailable'?'not_tested':'configuration',method:'GET مصفوفة موارد تجريبية بهويات مصرح بها؛ بلا استغلال أو كتابة',impact:scope,fixSteps:[c.recommendation],verification:['نجاح وصول المالكين قبل اختبار الحساب الآخر والزائر.'],references:[]};
   checks.push(c);onCheck?.(c);
   if(c.status==='fail')findings.push({id:c.id,rule:c.rule,category:'security',severity:'high',confidence:'high',title:c.title+' — كشف مورد',description:scope,url:c.url,evidence:c.evidence,recommendation:c.recommendation,checks:['أعد وصول المالك والحساب الآخر والزائر بعد الإصلاح.'],security:{group:'api',basis:'configuration',method:'GET لمورد تجريبي معلوم، بمصفوفة هويات مصرح بها',impact:'قراءة غير مصرح بها للمورد المحدد.',fixSteps:[c.recommendation],verification:['إعادة مصفوفة القراءة مع نجاح baseline أولًا.'],references:[]}});
 }
 return {checks,findings};
}
