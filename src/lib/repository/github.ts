import {createHash} from 'node:crypto';
import {requestResource} from '../network';
import type {HttpPage} from '../types';
export class UnsupportedRepositoryFile extends Error{constructor(){super('ملف ثنائي أو ترميز غير مدعوم؛ يدعم الفحص نص UTF-8 فقط.');}}
export type RepositoryTarget={owner:string;name:string};
export type RepositoryFile={path:string;sha:string;size:number;mode:string};
export type Snapshot={commit:string;tree:string;files:RepositoryFile[];truncated:boolean;excluded:number};
export type GitHubTransport=(url:string,options:{headers:Record<string,string>;signal?:AbortSignal;maxResponseBytes?:number})=>Promise<HttpPage>;
const identifier=/^[a-zA-Z0-9_.-]{1,100}$/;
export function parseRepository(input:string):RepositoryTarget{
 let url:URL;try{url=new URL(input.trim());}catch{throw new Error('أدخل رابط GitHub كاملًا بصيغة https://github.com/owner/repository');}
 // Reject dot-segment normalization as well as embedded credentials and refs.
 if(url.protocol!=='https:'||url.hostname!=='github.com'||url.port||url.username||url.password||url.search||url.hash||/(?:^|\/)\.\.?\//.test(input)||/%|\\/.test(input))throw new Error('استخدم رابط المستودع على github.com فقط دون توكن أو فرع في الرابط');
 const parts=url.pathname.replace(/\/$/,'').slice(1).split('/');if(parts.length!==2)throw new Error('أدخل رابط المستودع فقط ثم اختر الفرع في الحقل المخصص');const [owner,name]=[parts[0],parts[1].replace(/\.git$/,'')];if(!identifier.test(owner)||!identifier.test(name)||[owner,name].some(x=>x==='.'||x==='..'))throw new Error('اسم المستودع غير صالح');return {owner,name};
}
export function validBranch(branch:string){if(!branch||branch.length>200||/[\x00-\x20~^:?*\[\\]/.test(branch)||branch.includes('..')||branch.includes('@{')||branch.startsWith('-')||branch.startsWith('/')||branch.endsWith('/')||branch.endsWith('.lock'))throw new Error('اسم الفرع غير صالح');return branch;}
const shaPattern=/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;
export class GitHubReader{
 readonly base:string;
 constructor(readonly target:RepositoryTarget,private token='',private transport:GitHubTransport=(url,options)=>requestResource(url,options)){if(!identifier.test(target.owner)||!identifier.test(target.name))throw new Error('مستودع غير صالح');this.base=`https://api.github.com/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.name)}`;}
 private async json(path:string,signal?:AbortSignal,maxResponseBytes?:number):Promise<Record<string,unknown>>{
  if((path!==''&&!path.startsWith('/'))||/[\r\n]/.test(path))throw new Error('مسار GitHub غير صالح');
  const r=await this.transport(this.base+path,{headers:{accept:'application/vnd.github+json','x-github-api-version':'2026-03-10',...(this.token?{authorization:'Bearer '+this.token}:{})},signal,maxResponseBytes});
  if(r.status!==200){if([403,429].includes(r.status))throw new Error('GitHub رفض الطلب أو بلغ حد الاستخدام؛ تحقق من الصلاحيات وحد API. استخدم توكن قراءة للمستودع عند الحاجة.');if(r.status===401)throw new Error('توكن GitHub غير صالح أو منتهي؛ أعد الربط.');if(r.status===404)throw new Error('المستودع أو الفرع غير متاح؛ راجع الاسم وصلاحية Contents: read.');throw new Error('تعذر قراءة GitHub (HTTP '+r.status+')؛ لا تتبع التحويلات تلقائيًا.');}
  try{const data:unknown=JSON.parse(r.body);if(!data||typeof data!=='object'||Array.isArray(data))throw 0;return data as Record<string,unknown>;}catch{throw new Error('استجابة GitHub غير صالحة');}
 }
 async info(signal?:AbortSignal){const r=await this.json('',signal);const branch=typeof r.default_branch==='string'?validBranch(r.default_branch):'';if(!branch)throw new Error('المستودع فارغ أو لا يوجد فرع افتراضي');return {defaultBranch:branch,private:r.private===true};}
 async resolve(branch:string,signal?:AbortSignal){const r=await this.json('/commits/'+encodeURIComponent(validBranch(branch)),signal),tree=(r.commit as {tree?:{sha?:unknown}}|undefined)?.tree?.sha;if(typeof r.sha!=='string'||!shaPattern.test(r.sha)||typeof tree!=='string'||!shaPattern.test(tree))throw new Error('تعذر تثبيت نسخة commit من GitHub');return {commit:r.sha,tree};}
 async snapshot(branch:string,signal?:AbortSignal):Promise<Snapshot>{
  const ref=await this.resolve(branch,signal),r=await this.json('/git/trees/'+ref.tree+'?recursive=1',signal);if(!Array.isArray(r.tree)||typeof r.truncated!=='boolean')throw new Error('قائمة ملفات GitHub غير صالحة');
  const files:RepositoryFile[]=[];let excluded=0;
  for(const item of r.tree){if(!item||typeof item!=='object'){excluded++;continue;}const f=item as Record<string,unknown>;if(f.type==='tree')continue;
   if(f.type!=='blob'||!['100644','100755'].includes(String(f.mode))||typeof f.path!=='string'||f.path.length>1000||f.path.startsWith('/')||f.path.split('/').some(p=>p==='..'||p==='.'||!p)||/[\x00-\x1f\\]/.test(f.path)||typeof f.sha!=='string'||!shaPattern.test(f.sha)||!Number.isSafeInteger(f.size)||Number(f.size)<0){excluded++;continue;}
   files.push({path:f.path,sha:f.sha,size:Number(f.size),mode:String(f.mode)});
  }
  return {...ref,files,truncated:r.truncated,excluded};
 }
 async blob(file:RepositoryFile,signal?:AbortSignal){if(!shaPattern.test(file.sha)||file.size>(/(?:^|\/)(?:package-lock|npm-shrinkwrap)\.json$/.test(file.path)?4*1024*1024:256*1024))throw new Error('الملف يتجاوز حد 256KiB');const r=await this.json('/git/blobs/'+file.sha,signal,8*1024*1024);if(r.encoding!=='base64'||typeof r.content!=='string'||r.content.length>6*1024*1024)throw new Error('ملف GitHub ليس نصًا ضمن الحد المدعوم');const bytes=Buffer.from(r.content,'base64');if(bytes.length>(/(?:^|\/)(?:package-lock|npm-shrinkwrap)\.json$/.test(file.path)?4*1024*1024:256*1024)||bytes.length!==file.size )throw new Error('حجم الملف لا يطابق النسخة المثبتة');if(bytes.includes(0))throw new UnsupportedRepositoryFile();const actual=createHash(file.sha.length===40?'sha1':'sha256').update('blob '+bytes.length+'\0').update(bytes).digest('hex');if(actual.toLowerCase()!==file.sha.toLowerCase())throw new Error('محتوى الملف لا يطابق SHA المثبت');try{return new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{throw new UnsupportedRepositoryFile();}}
}
