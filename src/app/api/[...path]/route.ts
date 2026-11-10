import {parseApiConfig,verifyApiConfig} from '@/lib/api-tests';
import {NextRequest,NextResponse} from 'next/server';
import {resolveTxt} from 'node:dns/promises';
import {createHash} from 'node:crypto';
import {z} from 'zod';
import {getStore} from '@/lib/db';
import {hashPassword,verifyPassword} from '@/lib/auth';
import {collect,redact} from '@/lib/network';
import {credentialOriginAllowed} from '@/lib/repository/vault';
import {GitHubReader,parseRepository} from '@/lib/repository/github';
import {demoReport} from '@/lib/demo';
import {remediationPrompt,markdownReport,scanRemediationPrompt} from '@/lib/prompts';
import {enrichFinding} from '@/lib/ai';
import {scanCodeSnippet,scanUrlTarget} from '@/lib/api-v1-service';

export const runtime='nodejs';export const dynamic='force-dynamic';
class HttpError extends Error{constructor(public status:number,message:string){super(message);}}
const fail=(status:number,message:string):never=>{throw new HttpError(status,message);};
const credentials=z.object({email:z.email().max(200),password:z.string().min(12).max(200)});
const CORS_HEADERS={
  'Access-Control-Allow-Origin':'*',
  'Access-Control-Allow-Methods':'GET, POST, OPTIONS, DELETE',
  'Access-Control-Allow-Headers':'Content-Type, Authorization, x-api-key',
  'Access-Control-Max-Age':'86400',
};
async function body(req:NextRequest){if(!req.headers.get('content-type')?.includes('application/json'))fail(415,'استخدم JSON');const reader=req.body?.getReader();if(!reader)return {};const chunks:Uint8Array[]=[];let size=0;while(true){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>65536){await reader.cancel();fail(413,'حجم الطلب كبير');}chunks.push(part.value);}try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{fail(400,'طلب JSON غير صالح');}}
function sessionCookie(req:NextRequest,token:string,maxAge=604800){const origin=process.env.APP_ORIGIN??req.url;return {name:'aegis_session',value:token,httpOnly:true,secure:origin.startsWith('https:'),sameSite:'lax' as const,path:'/',maxAge};}
async function handler(req:NextRequest,ctx:{params:Promise<{path:string[]}>}){
  let isApiV1=false;
  try{
    const {path:segments}=await ctx.params;const path=segments.join('/');const store=getStore();const method=req.method;
    if(method==='OPTIONS')return new NextResponse(null,{status:204,headers:CORS_HEADERS});

    isApiV1=path==='v1'||path.startsWith('v1/')||path==='scan'||path.startsWith('scan/');
    if(isApiV1){
      if(process.env.API_KEY){
        const authHeader=req.headers.get('authorization')??'';
        const keyHeader=req.headers.get('x-api-key')??'';
        const bearerKey=authHeader.startsWith('Bearer ')?authHeader.slice(7).trim():'';
        if(keyHeader!==process.env.API_KEY&&bearerKey!==process.env.API_KEY){
          return NextResponse.json({success:false,error:'Unauthorized: Invalid or missing API key'},{status:401,headers:CORS_HEADERS});
        }
      }
      if(method==='GET'){
        if(path==='v1'||path==='v1/help'||path==='v1/docs'){
          return NextResponse.json({
            service:'Aegis Security Audit API',
            version:'1.0.0',
            description:'Automated security scanner for websites, code snippets, and APIs',
            endpoints:{
              scan:'POST /api/v1/scan (Universal: accepts url or code)',
              scanUrl:'POST /api/v1/scan/url',
              scanCode:'POST /api/v1/scan/code',
              health:'GET /api/v1/health'
            },
            examples:{
              scanUrl:'curl -X POST https://talabati-api.apps.taqat.academy/api/v1/scan -H "Content-Type: application/json" -d \'{"url":"https://example.com"}\'',
              scanCode:'curl -X POST https://talabati-api.apps.taqat.academy/api/v1/scan -H "Content-Type: application/json" -d \'{"code":"eval(cmd);","filename":"app.js"}\''
            }
          },{headers:CORS_HEADERS});
        }
        if(path==='v1/health')return NextResponse.json({success:true,status:'healthy',workerOnline:store.workerOnline(),timestamp:new Date().toISOString()},{headers:CORS_HEADERS});
      }
      if(method==='POST'){
        if(path==='v1/scan'||path==='scan'){
          const raw=await body(req);
          if(typeof raw.code==='string')return NextResponse.json(scanCodeSnippet(raw.code,raw.filename),{headers:CORS_HEADERS});
          if(typeof raw.url==='string')return NextResponse.json(await scanUrlTarget(raw.url,req.signal),{headers:CORS_HEADERS});
          return NextResponse.json({success:false,error:'يرجى تزويد url أو code لفحصه'},{status:400,headers:CORS_HEADERS});
        }
        if(path==='v1/scan/code'||path==='scan/code'){
          const raw=await body(req);
          if(typeof raw.code!=='string')return NextResponse.json({success:false,error:'حقل code مطلوب'},{status:400,headers:CORS_HEADERS});
          return NextResponse.json(scanCodeSnippet(raw.code,raw.filename),{headers:CORS_HEADERS});
        }
        if(path==='v1/scan/url'||path==='scan/url'){
          const raw=await body(req);
          if(typeof raw.url!=='string')return NextResponse.json({success:false,error:'حقل url مطلوب'},{status:400,headers:CORS_HEADERS});
          return NextResponse.json(await scanUrlTarget(raw.url,req.signal),{headers:CORS_HEADERS});
        }
      }
    }

    if(!['GET','HEAD'].includes(method)){
      const expected=new URL(process.env.APP_ORIGIN??req.url).origin;
      if(req.headers.get('origin')!==expected)fail(403,'مصدر الطلب غير مسموح');
    }
    if(path==='health'&&method==='GET')return NextResponse.json({ok:true,workerOnline:store.workerOnline(),worker:store.workerInfo()});
    if(['auth/login','auth/register'].includes(path)&&method==='POST'){
      if(!store.allow('auth-global',80,15*60000))fail(429,'طلبات كثيرة؛ حاول لاحقًا');
      const parsed=credentials.safeParse(await body(req));if(!parsed.success)fail(400,'أدخل بريدًا صحيحًا وكلمة مرور بين 12 و200 حرف');const c=parsed.data!;
      const key=createHash('sha256').update(c.email.toLowerCase()).digest('hex');if(!store.allow('auth:'+key,12,15*60000))fail(429,'طلبات كثيرة لهذا الحساب؛ حاول لاحقًا');
      let user=store.userByEmail(c.email);
      if(path==='auth/register'){if(process.env.REGISTRATION_OPEN==='false')fail(403,'التسجيل التجريبي مغلق حاليًا');if(user)fail(400,'تعذر إنشاء الحساب بهذا البريد');user=store.createUser(c.email,hashPassword(c.password));}
      else if(!user||!verifyPassword(c.password,user.password_hash))fail(401,'البريد أو كلمة المرور غير صحيحة');
      const token=store.createSession(user!.id);const response=NextResponse.json({user:{id:user!.id,email:user!.email}});response.cookies.set(sessionCookie(req,token));return response;
    }
    const token=req.cookies.get('aegis_session')?.value??'';const user=store.sessionUser(token);if(!user)fail(401,'يرجى تسجيل الدخول');const owner=user!.id;
    if(path==='auth/logout'&&method==='POST'){store.deleteSession(token);const response=NextResponse.json({ok:true});response.cookies.set(sessionCookie(req,'',0));return response;}
    if(path==='state'&&method==='GET')return NextResponse.json({user,projects:store.projects(owner),scans:store.scans(owner),repositories:store.repositories(owner),apiConfigs:store.projects(owner).flatMap(p=>{const c=store.apiConfig(owner,p.id);return c?[c]:[];}),workerOnline:store.workerOnline(),worker:store.workerInfo(),ai:{provider:'Ollama',model:process.env.OLLAMA_MODEL??'qwen2.5:1.5b',vision:false,patch:false}});
    if(path==='projects'&&method==='POST'){
      const input=z.object({name:z.string().trim().min(2).max(80),url:z.url().max(2048)}).safeParse(await body(req));if(!input.success)fail(400,'اسم المشروع أو الرابط غير صالح');const c=input.data!;
      return NextResponse.json({project:store.createProject(owner,c.name,c.url)});
    }
    if(path==='demo'&&method==='POST'){
      if(!store.allow('demo:'+owner,10,86400000))fail(429,'وصلت إلى حد التقارير التوضيحية');
      const p=store.projects(owner).find(p=>p.name==='مشروع توضيحي')??store.createProject(owner,'مشروع توضيحي','https://academy.example/');
      return NextResponse.json({scan:store.addDemo(owner,p,demoReport())});
    }
    if(segments[0]==='projects'&&segments[1]){
      const project=store.ownedProject(owner,segments[1]);if(!project)fail(404,'المشروع غير موجود');const p=project!;
      if(segments.length===2&&method==='DELETE'){store.deleteProject(owner,p.id);return NextResponse.json({ok:true});}
      if(segments[2]==='api-tests'&&segments.length===3){
        if(method==='GET')return NextResponse.json({config:store.apiConfig(owner,p.id)});
        if(method==='DELETE'){store.deleteApiConfig(owner,p.id);return NextResponse.json({ok:true});}
        if(method==='POST'){
          if(!credentialOriginAllowed(process.env.APP_ORIGIN??req.url))fail(400,'إرسال access tokens يتطلب HTTPS أو localhost للتطوير');
          if(!store.allow('api-config:'+owner,20,3600000))fail(429,'محاولات كثيرة؛ حاول لاحقًا');
          const raw=await body(req);if(raw.action==='verify')return NextResponse.json({config:await verifyApiConfig(store,owner,p.id,req.signal)});
          return NextResponse.json({config:store.saveApiConfig(owner,p.id,parseApiConfig(raw))});
        }
      }
      if(segments[2]==='repository'&&segments.length===3){
        if(method==='GET')return NextResponse.json({repository:store.repository(owner,p.id)});
        if(method==='DELETE'){store.unlinkRepository(owner,p.id);return NextResponse.json({ok:true});}
        if(method==='POST'){
          if(!store.allow('repository-link:'+owner,15,3600000))fail(429,'محاولات ربط كثيرة؛ حاول لاحقًا');
          const input=z.object({url:z.string().max(500),branch:z.string().trim().max(200).optional(),token:z.string().max(255).regex(/^(?:github_pat_[A-Za-z0-9_]{20,240})?$/).optional(),authorized:z.literal(true)}).parse(await body(req));
          if(input.token&&!credentialOriginAllowed(process.env.APP_ORIGIN??req.url))fail(400,'إرسال توكن GitHub يتطلب HTTPS أو تشغيل localhost للتطوير');
          const target=parseRepository(input.url),reader=new GitHubReader(target,input.token??''),signal=AbortSignal.any([req.signal,AbortSignal.timeout(20000)]);
          const info=await reader.info(signal),branch=input.branch||info.defaultBranch;await reader.resolve(branch,signal);
          return NextResponse.json({repository:store.linkRepository(owner,p.id,{...target,branch,private:info.private},input.token??'')});
        }
      }
      if(segments[2]==='verify'&&method==='POST'){
        if(!store.allow('verify:'+owner,10,3600000))fail(429,'محاولات تحقق كثيرة؛ حاول لاحقًا');
        const input=await body(req);let verified=false;
        if(input.method==='dns'){
          try{const records=await Promise.race([resolveTxt('_aegis-audit.'+new URL(p.url).hostname),new Promise<never>((_,reject)=>{const t=setTimeout(()=>reject(new Error('DNS timeout')),5000);t.unref();})]);verified=records.some(record=>record.join('')==='aegis-audit='+p.token);}catch{}
        }else if(input.method==='file'){
          const r=await collect(new URL('/.well-known/aegis-audit.txt',p.url).href,new URL(p.url).origin);verified=r.status===200&&r.body.trim()===p.token;
        }else fail(400,'اختر تحقق DNS أو ملف');
        if(!verified)fail(400,'لم يعثر على رمز التحقق المطابق؛ راجع الملف أو سجل DNS وانتظر انتشاره');
        store.verifyProject(owner,p.id);return NextResponse.json({project:store.ownedProject(owner,p.id)});
      }
      if(segments[2]==='scan'&&method==='POST'){const input=z.object({authorized:z.boolean(),kind:z.enum(['url','repository']).optional(),dependencyAudit:z.boolean().optional(),runtimeSecurity:z.boolean().optional(),apiTests:z.boolean().optional(),mode:z.enum(['full','quick']).optional(),maxPages:z.number().int().min(1).max(10000).optional()}).parse(await body(req));if(input.authorized!==true)fail(400,'يلزم إقرار صلاحية فحص الهدف المختار');return NextResponse.json({scan:store.queueScan(owner,p.id,{kind:input.kind,dependencyAudit:input.dependencyAudit,runtimeSecurity:input.runtimeSecurity,apiTests:input.apiTests,mode:input.mode,maxPages:input.maxPages})});}
    }
    if(segments[0]==='scans'&&segments[1]){
      const found=store.ownedScan(owner,segments[1]);if(!found)fail(404,'التقرير غير موجود');const scan=found!;
      if(segments.length===2&&method==='GET')return NextResponse.json({scan});
      if(segments[2]==='cancel'&&method==='POST'){store.cancelScan(owner,scan.id);return NextResponse.json({ok:true});}
      if(segments[2]==='prompt'&&segments.length===3&&method==='POST'){const selection=z.object({findingIds:z.array(z.string().max(200)).max(2000).optional()}).parse(await body(req));return NextResponse.json({prompt:scanRemediationPrompt(scan,selection.findingIds)});}
      if(segments[2]==='checks'&&method==='GET')return NextResponse.json({scanId:scan.id,engine:scan.result?.engine,checks:scan.result?.checks??[]});
      if(segments[2]==='export'&&method==='GET')return NextResponse.json({markdown:markdownReport(scan)});
      if(segments[2]==='findings'&&segments[3]&&method==='POST'){
        const f=scan.result?.findings.find(f=>f.id===segments[3]);if(!f)fail(404,'المشكلة غير موجودة');
        if(segments[4]==='prompt')return NextResponse.json({prompt:remediationPrompt(f!)});
        if(segments[4]==='explain'){
          if(!store.allow('ai:'+owner,10,3600000))fail(429,'وصلت إلى حد طلبات AI التجريبي');
          return NextResponse.json({analysis:await enrichFinding(f!),source:'ollama',verified:false});
        }
      }
    }
    fail(404,'العملية غير موجودة');
  }catch(e){const status=e instanceof HttpError?e.status:400;const headers=isApiV1?CORS_HEADERS:undefined;return NextResponse.json({success:false,error:e instanceof z.ZodError?'مدخلات غير صالحة':redact(e instanceof Error?e.message:'تعذر تنفيذ الطلب').slice(0,300)},{status,headers});}
}
export {handler as GET,handler as POST,handler as DELETE,handler as OPTIONS};
