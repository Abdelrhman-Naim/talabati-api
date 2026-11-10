export class ApiError extends Error{constructor(public status:number,message:string){super(message);}}
export async function api(path:string,method='GET',body?:unknown){
 const endpoint='/api/'+path;
 let r:Response;
 try{r=await fetch(endpoint,{method,headers:body!==undefined?{'Content-Type':'application/json'}:undefined,body:body!==undefined?JSON.stringify(body):undefined,cache:'no-store',signal:AbortSignal.timeout(path.endsWith('/explain')?95000:15000)});}
 catch(e){throw new ApiError(0,`تعذر الاتصال أو انتهت مهلة ${endpoint}؛ تحقق من تشغيل السيرفر.`);}
 const raw=await r.text();let data;try{data=JSON.parse(raw);}catch{throw new ApiError(r.status,`استجابة غير صالحة من ${endpoint} (HTTP ${r.status})؛ تحقق من المسار وتشغيل Next.js.`);}
 if(!r.ok)throw new ApiError(r.status,`${data.error??'تعذر تنفيذ الطلب'} (${endpoint} • HTTP ${r.status})`);return data;
}
