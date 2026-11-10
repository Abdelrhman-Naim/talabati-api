import {redact} from '../redaction';
export type InstalledPackage={name:string;version:string;file:string;line:number};
export const exactVersion=/^\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?$/;
const packageName=/^(?:@[a-zA-Z0-9_.-]+\/)?[a-zA-Z0-9_.-]+$/;
export function isNpmLockfile(file:string){return /(?:^|\/)(?:package-lock|npm-shrinkwrap)\.json$/.test(file);}
export function parseLockfile(file:string,body:string){
 const data:unknown=JSON.parse(body);if(!data||typeof data!=='object'||Array.isArray(data))throw new Error('بنية lockfile غير صالحة');
 const root=data as Record<string,unknown>,out=new Map<string,InstalledPackage>(),lines=body.split('\n'),locations=new Map<string,number>();for(let i=0;i<lines.length;i++){const m=lines[i].match(/^\s*("(?:\\.|[^"\\])*")\s*:/);if(m){try{const key=JSON.parse(m[1]);if(!locations.has(key))locations.set(key,i+1);}catch{}}}let incomplete=false,seen=0;
 function add(name:string,entry:unknown,key:string){if(!entry||typeof entry!=='object'){incomplete=true;return;}const e=entry as Record<string,unknown>;if(e.link===true)return;if(name.length>214||redact(name)!==name||!packageName.test(name)||typeof e.version!=='string'||!exactVersion.test(e.version)){incomplete=true;return;}if(e.resolved&&typeof e.resolved==='string'){try{const u=new URL(e.resolved);if(u.protocol!=='https:'||u.hostname!=='registry.npmjs.org'){incomplete=true;return;}}catch{incomplete=true;return;}}const id=name+'@'+e.version;if(!out.has(id))out.set(id,{name,version:e.version,file,line:locations.get(key)??1});}
 if([2,3].includes(Number(root.lockfileVersion))&&root.packages&&typeof root.packages==='object'&&!Array.isArray(root.packages)){
  for(const [path,entry]of Object.entries(root.packages)){if(!path)continue;if(++seen>10000){incomplete=true;break;}if(!path.includes('node_modules/')){incomplete=true;continue;}const e=entry as Record<string,unknown>;const name=typeof e?.name==='string'?e.name:path.split('node_modules/').at(-1)!;add(name,entry,path);}
 }else if(Number(root.lockfileVersion)===1&&root.dependencies&&typeof root.dependencies==='object'){
  const walk=(deps:Record<string,unknown>,depth=0)=>{if(depth>20){incomplete=true;return;}for(const [name,e]of Object.entries(deps)){if(++seen>10000){incomplete=true;return;}add(name,e,name);if(e&&typeof e==='object'){const child=(e as {dependencies?:unknown}).dependencies;if(child&&typeof child==='object'&&!Array.isArray(child))walk(child as Record<string,unknown>,depth+1);}}};walk(root.dependencies as Record<string,unknown>);
 }else throw new Error('يدعم فحص OSV ملفات npm lock بإصدار 1 أو 2 أو 3 فقط');
 return {packages:[...out.values()],incomplete};
}
