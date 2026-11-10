export async function withDeadline<T>(operation:Promise<T>,ms:number,onTimeout:()=>unknown|Promise<unknown>):Promise<T>{
 let timer:ReturnType<typeof setTimeout>|undefined;
 const deadline=new Promise<never>((_,reject)=>{timer=setTimeout(()=>{try{Promise.resolve(onTimeout()).catch(()=>{});}catch{}reject(new Error('انتهت مهلة عملية المتصفح'));},ms);});
 try{return await Promise.race([operation,deadline]);}finally{clearTimeout(timer);}
}
