import {validateTarget} from './network';
import {secretCount} from './checks';
export function resourcePolicy(url:string,method:string,headers:Record<string,string>,navigation:boolean,origin:string){
 const target=validateTarget(url);
 if(!['GET','HEAD'].includes(method))throw new Error('تم حظر طلب كتابة أثناء الفحص السلبي');
 if(navigation&&target.origin!==origin)throw new Error('تنقل خارج النطاق المخول');
 if(secretCount(JSON.stringify(headers))>0)throw new Error('تم حظر استخدام مفتاح إداري ظاهر في طلب الصفحة');
 const allowed:Record<string,string>={};
 for(const [name,value] of Object.entries(headers))if(['accept','accept-language','authorization','apikey','content-type','origin','referer','cookie','user-agent'].includes(name.toLowerCase()))allowed[name.toLowerCase()]=value;
 return allowed;
}
