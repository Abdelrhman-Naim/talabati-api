import {load} from 'cheerio';
import {validateTarget,decodeBody} from './network';
import type {CrawlOptions} from './types';
export function resolveCrawlOptions(input:{mode?:'full'|'quick';maxPages?:number}={}):CrawlOptions{
 const mode=input.mode??'full',full=mode==='full';
 const bounded=(n:number,fallback:number,min:number,max:number)=>Math.max(min,Math.min(max,Number.isFinite(n)&&n>0?Math.floor(n):fallback));
 return {mode,maxPages:bounded(input.maxPages??Number(full?process.env.CRAWL_MAX_PAGES:process.env.MAX_SCAN_PAGES),full?5000:5,1,full?10000:100),maxDurationMs:bounded(Number(full?process.env.CRAWL_MAX_DURATION_MS:process.env.MAX_SCAN_DURATION_MS),full?3600000:60000,10000,full?14400000:180000)};
}
export function normalizeCrawlUrl(input:string,base:string,origin:string,kind:'page'|'resource'='page'):string|null{
 try{
  const raw=new URL(input,base);if(raw.href.length>2048)return null;
  const u=validateTarget(raw.href);if(u.origin!==origin)return null;
  const path=decodeURIComponent(u.pathname);
  if(/(?:^|\/)(?:logout|signout|sign-out|delete|remove|checkout|purchase|unsubscribe)(?:[\/_-]|$)/i.test(path))return null;
  if(kind==='page'&&/\.(?:png|jpe?g|gif|webp|svg|ico|pdf|zip|gz|mp[34]|webm|woff2?|ttf|css|m?js|map|xml|txt|docx?|xlsx?|pptx?)$/i.test(path))return null;
  if([...u.searchParams].length>8)return null;
  for(const [key,value] of [...u.searchParams]){
   if(/^(?:utm_.+|gclid|fbclid|msclkid)$/i.test(key)){u.searchParams.delete(key);continue;}
   if(/token|session|password|secret|csrf|nonce|authorization/i.test(key)||value.length>512||/^(?:action|do)$/i.test(key)&&/delete|remove|logout|buy|checkout/i.test(value))return null;
  }
  u.searchParams.sort();return u.href;
 }catch{return null;}
}
type Rule={path:string;allow:boolean};
export function parseRobots(body:string,agent='AegisAuditBeta'){
 const groups:{agents:string[];rules:Rule[];directives:boolean}[]=[];const sitemaps:string[]=[];let group:{agents:string[];rules:Rule[];directives:boolean}|undefined;
 for(const line of body.replace(/^\uFEFF/,'').split(/\r?\n/)){
  const clean=line.split('#')[0].trim(),at=clean.indexOf(':');if(at<0)continue;
  const key=clean.slice(0,at).trim().toLowerCase(),value=clean.slice(at+1).trim();
  if(key==='sitemap'){if(value)sitemaps.push(value);continue;}
  if(key==='user-agent'){if(!group||group.directives){group={agents:[],rules:[],directives:false};groups.push(group);}group.agents.push(value.toLowerCase());continue;}
  if(group&&(key==='allow'||key==='disallow')){group.directives=true;if(value)group.rules.push({path:value,allow:key==='allow'});}
 }
 const matching=groups.map(g=>({g,specificity:Math.max(-1,...g.agents.map(a=>a==='*'?0:agent.toLowerCase().includes(a)?a.length:-1))})).filter(g=>g.specificity>=0);
 const highest=Math.max(-1,...matching.map(g=>g.specificity));const rules=matching.filter(g=>g.specificity===highest).flatMap(g=>g.g.rules);
 return {sitemaps:[...new Set(sitemaps)],allowed(url:string){const u=new URL(url),target=u.pathname+u.search;let best=-1,allow=true;
  const canonical=(value:string)=>encodeURI(value).replace(/%25([0-9a-f]{2})/gi,'%$1').replace(/%[0-9a-f]{2}/gi,m=>{const c=String.fromCharCode(parseInt(m.slice(1),16));return /[a-z0-9._~-]/i.test(c)?c:m.toUpperCase();});
  for(const rule of rules){const exact=rule.path.endsWith('$'),pattern=canonical(exact?rule.path.slice(0,-1):rule.path),chunks=pattern.split('*'),text=canonical(target);let match=text.startsWith(chunks[0]),pos=chunks[0].length;
   for(let i=1;match&&i<chunks.length;i++){const chunk=chunks[i];if(exact&&i===chunks.length-1){match=text.endsWith(chunk)&&text.length-chunk.length>=pos;pos=text.length;}else{const at=text.indexOf(chunk,pos);if(at<0)match=false;else pos=at+chunk.length;}}
   if(chunks.length===1&&exact&&pos!==text.length)match=false;
   if(match){const length=pattern.replaceAll('*','').length;if(length>best||length===best&&rule.allow){best=length;allow=rule.allow;}}
  }return allow;
 }};
}
export function parseSitemap(input:string|Uint8Array):{kind:'index'|'pages'|'invalid';urls:string[]}{
 const bytes=typeof input==='string'?null:Buffer.from(input);const body=bytes?decodeBody(bytes,bytes[0]===0x1f&&bytes[1]===0x8b?'gzip':undefined).toString('utf8'):input as string;
 if(/<!DOCTYPE|<!ENTITY/i.test(body))return {kind:'invalid',urls:[]};
 const $=load(body,{xml:true});const root=$.root().children().first();const name=(root.get(0)?.tagName??'').split(':').at(-1);
 const kind=name==='sitemapindex'?'index':name==='urlset'?'pages':'invalid';if(kind==='invalid')return {kind,urls:[]};
 const urls:string[]=[];$('*').each((_,el)=>{if(el.type==='tag'&&el.tagName.split(':').at(-1)==='loc'&&el.parent?.type==='tag'&&['url','sitemap'].includes(el.parent.tagName.split(':').at(-1)??'')){const value=$(el).text().trim();if(value)urls.push(value);}});
 return {kind,urls:[...new Set(urls)]};
}
