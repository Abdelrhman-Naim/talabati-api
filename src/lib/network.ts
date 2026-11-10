import {redact} from './redaction';
export {redact} from './redaction';
import {lookup} from 'node:dns/promises';
import {isIP} from 'node:net';
import http from 'node:http';
import https from 'node:https';
import ipaddr from 'ipaddr.js';
import {gunzipSync,inflateSync,brotliDecompressSync} from 'node:zlib';
import type {HttpPage} from './types';

export function assertPublicAddress(address:string){
  let parsed;try{parsed=ipaddr.parse(address.replace(/^\[|\]$/g,''));}catch{throw new Error('عنوان شبكة غير صالح');}
  if(parsed.kind()==='ipv6'&&(parsed as ipaddr.IPv6).isIPv4MappedAddress()) parsed=(parsed as ipaddr.IPv6).toIPv4Address();
  if(parsed.range()!=='unicast') throw new Error('الوصول إلى الشبكات الخاصة أو المحجوزة غير مسموح');
}
export function validateTarget(input:string){
  const u=new URL(input);
  if(!['http:','https:'].includes(u.protocol)||u.username||u.password||(u.port&&!['80','443'].includes(u.port))) throw new Error('أدخل رابط HTTP أو HTTPS عامًا بلا بيانات اعتماد أو منفذ مخصص');
  const h=u.hostname.replace(/^\[|\]$/g,'').toLowerCase();
  if(h==='localhost'||!h.includes('.')&&!h.includes(':')||/\.(local|localhost|internal|test|invalid)$/.test(h)) throw new Error('النطاق المحلي غير مسموح');
  if(isIP(h)) assertPublicAddress(h);
  u.hash='';let decoded=u.href;try{decoded=decodeURIComponent(decoded);}catch{}
  if(redact(decoded)!==decoded)throw new Error('الرابط يحتوي سرًا محتملًا؛ احذفه من الرابط قبل حفظ المشروع');
  return u;
}
export function assertResolved(addresses:{address:string;family:number}[]){if(!addresses.length)throw new Error('تعذر حل النطاق');for(const a of addresses)assertPublicAddress(a.address);}
export function pinnedLookup(pinned:{address:string;family:number}){return (_host:string,options:{all?:boolean},cb:(error:Error|null,address:unknown,family?:number)=>void)=>options.all?cb(null,[pinned]):cb(null,pinned.address,pinned.family);}


export function decodeBody(raw:Buffer,encoding:string|undefined,max=2*1024*1024){
 if(encoding==='gzip')return gunzipSync(raw,{maxOutputLength:max});
 if(encoding==='br')return brotliDecompressSync(raw,{maxOutputLength:max});
 if(encoding==='deflate')return inflateSync(raw,{maxOutputLength:max});
 if(encoding&&encoding!=='identity')throw new Error('ترميز استجابة غير مدعوم');
 if(raw.length>max)throw new Error('تجاوز الحجم المسموح');return raw;
}
export function decodeHttpResponseBody(raw:Buffer,encoding:string|undefined,max:number,method:string,status:number){return method==='HEAD'||status===204||status===304?Buffer.alloc(0):decodeBody(raw,encoding,max);}
export async function resolvePublicHostname(hostname:string,signal?:AbortSignal,resolver:(hostname:string)=>Promise<{address:string;family:number}[]>=name=>lookup(name,{all:true})){
 signal?.throwIfAborted();let timer:ReturnType<typeof setTimeout>|undefined;let abort:()=>void=()=>{};
 const deadline=new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(new Error('انتهت مهلة DNS')),5000);timer.unref();abort=()=>reject(new Error('أُلغي انتظار DNS'));signal?.addEventListener('abort',abort,{once:true});});
 try{return await Promise.race([resolver(hostname),deadline]);}finally{if(timer)clearTimeout(timer);signal?.removeEventListener('abort',abort);}
}
export async function requestResource(input:string,options:{origin?:string;method?:'GET'|'HEAD'|'OPTIONS'|'POST';body?:string;maxResponseBytes?:number;headers?:Record<string,string>;signal?:AbortSignal}={}):Promise<HttpPage>{
  options.signal?.throwIfAborted();
  const origin=options.origin;const maxResponse=Math.min(8*1024*1024,Math.max(1,options.maxResponseBytes??2*1024*1024));
  if(options.body&&Buffer.byteLength(options.body)>65536)throw new Error('حجم طلب الخدمة يتجاوز الحد');
  if(options.method==='POST'&&input!=='https://api.osv.dev/v1/querybatch')throw new Error('طلبات POST محصورة بخدمة OSV المعتمدة');
  const u=validateTarget(input);if(origin&&u.origin!==origin)throw new Error('إعادة توجيه أو طلب خارج النطاق المعتمد');
  const hostname=u.hostname.replace(/^\[|\]$/g,'');
  const addresses=await resolvePublicHostname(hostname,options.signal);
  options.signal?.throwIfAborted();assertResolved(addresses);const pinned=addresses.find(a=>a.family===4)??addresses[0];const start=Date.now();
  const response=await new Promise<HttpPage>((resolve,reject)=>{
    const transport=u.protocol==='https:'?https:http;
    const req=transport.request(u,{method:options.method??'GET',signal:options.signal,agent:false,headers:{'user-agent':'AegisAuditBeta/0.5 (authorized passive audit)','accept':'*/*',...options.headers,'accept-encoding':'identity'},lookup:pinnedLookup(pinned) as never},res=>{
      const chunks:Buffer[]=[];let bytes=0;
      res.on('data',(chunk:Buffer)=>{bytes+=chunk.length;if(bytes>maxResponse){req.destroy(new Error('تجاوز حجم الصفحة 2MB'));return;}chunks.push(chunk);});
      res.on('error',reject);res.on('end',()=>{try{const headers:Record<string,string>={};for(const [k,v] of Object.entries(res.headers)){if(v!==undefined)headers[k]=Array.isArray(v)?v.join('\n'):v;}const raw=decodeHttpResponseBody(Buffer.concat(chunks),headers['content-encoding'],maxResponse,options.method??'GET',res.statusCode??0);delete headers['content-encoding'];delete headers['content-length'];resolve({url:u.href,status:res.statusCode??0,headers,body:raw.toString('utf8'),rawBody:raw,elapsedMs:Date.now()-start,bytes});}catch(e){reject(e);}});
    });
    const timer=setTimeout(()=>req.destroy(new Error('انتهت مهلة جلب الصفحة')),15000);req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end(options.body);
  });
  return response;
}
export type CollectOptions={signal?:AbortSignal;allowUrl?:(url:string)=>boolean;transport?:typeof requestResource};
export async function collect(input:string,origin?:string,hop=0,options:CollectOptions={}):Promise<HttpPage>{
  options.signal?.throwIfAborted();if(options.allowUrl&&!options.allowUrl(input))throw new Error('الوجهة مستبعدة حسب سياسة الزحف');
  if(hop>3)throw new Error('تجاوز حد إعادة التوجيه');const u=validateTarget(input);const response=await (options.transport??requestResource)(u.href,{origin,signal:options.signal});
  options.signal?.throwIfAborted();
  if([301,302,303,307,308].includes(response.status)){
    if(!response.headers.location)throw new Error('إعادة توجيه بلا وجهة');
    const next=new URL(response.headers.location,u);if(next.origin!==u.origin)throw new Error('إعادة التوجيه تتطلب اعتماد الرابط النهائي كمشروع مستقل');
    return collect(next.href,origin??u.origin,hop+1,options);
  }
  return response;
}
