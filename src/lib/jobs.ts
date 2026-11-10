import {normalizeLegacyResult} from './findings-adapter';
import {runAutomaticApiHttp,identityCapability,type ApiHttpTransport} from './auto-api-http';
import {mergeApiServices} from './api-discovery';
import {setTimeout as pause} from 'node:timers/promises';
import {analyze,coverage} from './audit';
import {withDeadline} from './deadline';
import {SCORE_VERSION} from './scoring';
import {collect,redact,validateTarget} from './network';
import {normalizeCrawlUrl,parseRobots,parseSitemap,resolveCrawlOptions} from './crawler';
import type {Store} from './db';
import type {HttpPage,Scan,ScanResult,ScanEvent} from './types';
type FetchPage=(url:string,origin?:string,signal?:AbortSignal,progress?:(message:string)=>void,allowed?:(url:string)=>boolean)=>Promise<HttpPage>;
export async function runJob(store:Store,job:Scan,fetchPage:FetchPage=(url,origin,signal,_progress,allowed)=>collect(url,origin,0,{signal,allowUrl:allowed}),delay=250,options:{budgetMs?:number;requestTimeoutMs?:number;fetchDiscovery?:FetchPage;apiHttpTransport?:ApiHttpTransport}={}){
 const project=store.ownedProject(job.owner_id,job.project_id);if(!project)return;
 const config=job.crawlOptions??resolveCrawlOptions({mode:'quick'}),budgetMs=options.budgetMs??config.maxDurationMs,max=config.maxPages;
 const result:ScanResult={findings:[],services:[],coverage:structuredClone(coverage),pages:[],errors:[],scope:redact(project.url),engine:'aegis-link-audit@0.12.0',capabilities:[identityCapability],apiDiscovery:{files:0,origins:0,excluded:0,limited:false},events:[],checks:[],scoreVersion:SCORE_VERSION,collection:{attempted:0,discovered:1,scriptAttempts:0,scriptSuccesses:0},crawl:{mode:config.mode,maxPages:max,maxDurationMs:budgetMs,remaining:1,skipped:0,failed:0,sitemaps:0,discoveryLimited:false,skippedSamples:[],discoveryWarnings:[]}};
 function mergeDiscovery(out:ReturnType<typeof analyze>){const capped=mergeApiServices(result.services,out.services);result.apiDiscovery!.files+=out.apiDiscovery?.files??0;result.apiDiscovery!.excluded+=out.apiDiscovery?.excluded??0;result.apiDiscovery!.limited=result.apiDiscovery!.limited||capped||Boolean(out.apiDiscovery?.limited);result.apiDiscovery!.origins=result.services.filter(s=>/API|Supabase/i.test(s.type)).length;}
 const crawl=result.crawl!,origin=new URL(project.url).origin,started=Date.now(),queue:string[]=[],pending=new Set<string>(),discovered=new Set<string>(),visited=new Set<string>(),resources=new Set<string>();
 const inventoryLimit=Math.min(40000,Math.max(10000,max*4));let cursor=0,eventId=0,lastPersist=0;
 let robots=parseRobots('');
 const syncCounts=()=>{result.collection!.discovered=discovered.size;crawl.remaining=pending.size;};
 const publish=(stage:string,force=false)=>{syncCounts();if(force||result.pages.length<3||Date.now()-lastPersist>=1000){store.progress(job.id,redact(stage),normalizeLegacyResult(result));lastPersist=Date.now();}};
 const event=(phase:ScanEvent['phase'],status:ScanEvent['status'],message:string,url?:string)=>{result.events!.push({id:String(++eventId),at:Date.now(),phase,status,message:redact(message),...(url?{url:redact(url)}:{})});if(result.events!.length>300)result.events!.splice(0,result.events!.length-300);publish(message);};
 const error=(message:string)=>{if(result.errors.length<500)result.errors.push(redact(message));};
 const skip=(url:string,reason:string)=>{crawl.skipped++;if(crawl.skippedSamples.length<15)crawl.skippedSamples.push({url:redact(url.split('?')[0]).slice(0,2048),reason});};
 const enqueue=(input:string,base=project.url)=>{
  const url=normalizeCrawlUrl(input,base,origin);if(!url){skip(input,'رابط خارج النطاق أو ليس صفحة قابلة للزحف أو يحمل معاملات حساسة');return;}
  if(discovered.has(url)||visited.has(url))return;
  if(discovered.size>=inventoryLimit){crawl.discoveryLimited=true;skip(url,'تجاوز سقف قائمة الاكتشاف');return;}
  discovered.add(url);pending.add(url);queue.push(url);syncCounts();
 };
 enqueue(project.url);
 const running=()=>store.isRunning(job.id);
 const fetchBounded=(url:string,discovery=false,extraLimit=Infinity,asset=false)=>{
  const remaining=Math.min(budgetMs-(Date.now()-started),extraLimit);if(remaining<=0)return Promise.reject(new Error('انتهت مهلة الفحص الكلية'));
  if(project.verified_until<Date.now())return Promise.reject(new Error('انتهى تفويض النطاق'));
  const controller=new AbortController(),loader=discovery?(options.fetchDiscovery??fetchPage):fetchPage;
  const allowed=(target:string)=>Boolean(normalizeCrawlUrl(target,url,origin,discovery||asset?'resource':'page'))&&(new URL(target).pathname==='/robots.txt'||robots.allowed(target));
  let rejectAbort:(reason:unknown)=>void=()=>{};const interrupted=new Promise<never>((_,reject)=>{rejectAbort=reject;});
  const abort=()=>rejectAbort(controller.signal.reason);controller.signal.addEventListener('abort',abort,{once:true});
  const watch=setInterval(()=>{if(!running()||project.verified_until<Date.now())controller.abort(new Error('أُلغي الفحص أو انتهى تفويضه'));},200);
  const work=Promise.resolve().then(()=>loader(url,origin,controller.signal,message=>{if(!controller.signal.aborted&&running())event('fetch','running',message,url);},allowed));
  return withDeadline(Promise.race([work,interrupted]),Math.min(options.requestTimeoutMs??(discovery?10000:25000),remaining),()=>controller.abort(new Error('انتهت مهلة جمع المورد'))).finally(()=>{clearInterval(watch);controller.signal.removeEventListener('abort',abort);});
 };
 if(config.mode==='full'){
  const discoveryEnd=Math.min(started+budgetMs,Date.now()+30000);
  event('discovery','running','قراءة robots.txt وخرائط الموقع لاكتشاف الصفحات');
  try{
   const r=await fetchBounded(new URL('/robots.txt',origin).href,true,discoveryEnd-Date.now());if(!running())return;
   if(r.status===200)robots=parseRobots(r.body);else if(![404,410].includes(r.status)){crawl.discoveryLimited=true;crawl.discoveryWarnings.push(`robots.txt: HTTP ${r.status}؛ قواعده لم تتوفر.`);}
  }catch(e){crawl.discoveryLimited=true;crawl.discoveryWarnings.push(redact(`تعذر قراءة robots.txt: ${e instanceof Error?e.message:'اتصال'}`));}
  if(!running())return;
  const absoluteMap=(value:string,base:string)=>{try{return new URL(value,base).href;}catch{return value;}};
  const declaredMaps=robots.sitemaps.map(value=>absoluteMap(value,origin));
  const maps=[...declaredMaps,new URL('/sitemap.xml',origin).href,new URL('/sitemap_index.xml',origin).href,new URL('/wp-sitemap.xml',origin).href],seenMaps=new Set<string>(),requiredMaps=new Set(declaredMaps);let mi=0;
  while(mi<maps.length&&seenMaps.size<50&&Date.now()<discoveryEnd&&running()){
   const raw=maps[mi++];let url:string;try{const u=validateTarget(new URL(raw,origin).href);if(u.origin!==origin)throw new Error();url=u.href;}catch{skip(raw,'خريطة خارج نطاق الموقع أو غير آمنة');continue;}
   if(seenMaps.has(url))continue;seenMaps.add(url);if(!robots.allowed(url)){skip(url,'مستبعد حسب robots.txt');continue;}
   try{
    event('discovery','running',`قراءة خريطة الموقع ${seenMaps.size}: ${url}`,url);
    const map=await fetchBounded(url,true,discoveryEnd-Date.now());if(!running())return;
    if([404,410].includes(map.status)){if(requiredMaps.has(url)){crawl.discoveryLimited=true;if(crawl.discoveryWarnings.length<30)crawl.discoveryWarnings.push(`خريطة معلنة غير متاحة: ${redact(url)} • HTTP ${map.status}`);}continue;}
    if(map.status!==200){crawl.discoveryLimited=true;if(crawl.discoveryWarnings.length<30)crawl.discoveryWarnings.push(`خريطة ${redact(url)}: HTTP ${map.status}`);continue;}
    const mapBase=validateTarget(map.url);if(mapBase.origin!==origin||!robots.allowed(mapBase.href))throw new Error('وجهة الخريطة النهائية خارج نطاق الزحف المسموح');
    const parsed=parseSitemap(map.rawBody??map.body);if(parsed.kind==='invalid'){if(requiredMaps.has(url)){crawl.discoveryLimited=true;crawl.discoveryWarnings.push('خريطة معلنة غير مقروءة: '+redact(url));}continue;}crawl.sitemaps++;
    if(parsed.kind==='index'){for(const value of parsed.urls){const child=absoluteMap(value,mapBase.href);requiredMaps.add(child);if(maps.length<1000)maps.push(child);else crawl.discoveryLimited=true;}}
    else for(const link of parsed.urls)enqueue(link,mapBase.href);
    event('discovery','done',`قرئت خريطة: ${parsed.urls.length} رابطًا، ${discovered.size} رابط صفحة مقبول حتى الآن`,url);
   }catch(e){crawl.discoveryLimited=true;if(crawl.discoveryWarnings.length<30)crawl.discoveryWarnings.push(redact(`تعذر قراءة ${url}: ${e instanceof Error?e.message:'اتصال'}`));}
  }
  if(mi<maps.length){crawl.discoveryLimited=true;if(crawl.discoveryWarnings.length<30)crawl.discoveryWarnings.push('لم تكتمل قراءة كل خرائط الموقع ضمن ميزانية الاكتشاف (30 ثانية / 50 خريطة).');}
  event('discovery','done',`اكتشاف أولي: ${discovered.size} روابط صفحات، ${crawl.sitemaps} خرائط مقروءة. يستمر الاكتشاف أثناء الزحف.`);
 }
 while(cursor<queue.length&&result.collection!.attempted<max&&Date.now()-started<budgetMs){
  if(!running())return;
  if(project.verified_until<Date.now()){crawl.stopReason='scope_expired';error('انتهى تفويض النطاق');break;}
  const url=queue[cursor++];if(!pending.delete(url)||visited.has(url))continue;
  if(!robots.allowed(url)){visited.add(url);skip(url,'مستبعد حسب robots.txt');syncCounts();continue;}
  visited.add(url);result.collection!.attempted++;syncCounts();
  try{
   event('fetch','running',`جمع الصفحة ${result.collection!.attempted} • مكتشف ${discovered.size} • متبقٍ ${pending.size}`,url);
   const page=await fetchBounded(url);if(!running())return;
   if(!normalizeCrawlUrl(page.url,project.url,origin)||!robots.allowed(page.url))throw new Error('وجهة الصفحة النهائية خارج نطاق صفحات الزحف');
   visited.add(page.url);pending.delete(page.url);
   if(result.pages.some(p=>p.url===redact(page.url)))continue;
   if(!/text\/html|application\/xhtml\+xml/i.test(page.headers['content-type']??'')){skip(url,'الاستجابة ليست HTML');event('fetch','warning','استبعد مورد غير HTML',url);continue;}
   if(page.collectorWarning&&!result.errors.includes(page.collectorWarning))error(page.collectorWarning);
   if(page.status>=400){crawl.failed++;error(`HTTP ${page.status}: ${url}`);}
   event('fetch',page.status>=400?'warning':'done',`وصلت استجابة HTTP ${page.status} • ${page.bytes} بايت`,page.url);
   event('analyze','running','تحليل سياسات الأمان والكوكيز والأسرار والمحتوى وقواعد الصفحة',page.url);
   const out=analyze(page);result.pages.push({url:redact(page.url),status:page.status,elapsedMs:page.elapsedMs,bytes:page.bytes});result.findings.push(...out.findings);result.checks!.push(...out.checks);
   if(page.browser){
    result.engine='aegis-browser-axe@0.12.0';result.collection!.scriptAttempts+=page.browser.scriptAttempts;result.collection!.scriptSuccesses+=page.browser.scriptSuccesses;
    for(const warning of page.browser.warnings)error('المتصفح: '+warning);
    result.pages[result.pages.length-1]={...result.pages[result.pages.length-1],browser:{lcp:page.browser.lcp,cls:page.browser.cls,domReady:page.browser.domReady,viewport:page.browser.viewport,observedMs:page.browser.observedMs}};
    result.network=[...(result.network??[]),...page.browser.requests].slice(0,300);
    for(const c of result.coverage){if(c.id==='technical')c.detail='HTTP وDOM المعروض وأخطاء JavaScript ضمن نافذة الفحص.';if(c.id==='seo')c.detail='HTML وDOM المعروض؛ لا يشمل Search Console أو إثبات الفهرسة.';if(c.id==='performance')c.detail='LCP وCLS مختبريان إن سجلا؛ INP الميداني غير متاح.';if(c.id==='accessibility')c.detail='axe على DOM المعروض وقواعد HTML؛ ليست شهادة امتثال.';if(c.id==='ux')c.detail='DOM وتمدد أفقي في viewport المحدد؛ ليست دراسة مستخدمين.';}
   }
   event('analyze','done',`اكتمل تحليل الأمان: ${out.checks.filter(c=>c.category==='security').length} قاعدة؛ إجمالي الصفحة: ${out.checks.length} نتيجة قاعدة و${out.findings.length} ملاحظة`,page.url);
   mergeDiscovery(out);
   if(page.status>=200&&page.status<300)for(const link of out.links)enqueue(link,page.url);
   publish(`فُحصت ${result.pages.length} صفحة • مكتشف ${discovered.size} • متبقٍ ${pending.size}`);
   for(const src of page.browser?[]:out.scripts){
    if(Date.now()-started>=budgetMs||resources.size>=3||resources.has(src)||!running())continue;resources.add(src);result.collection!.scriptAttempts++;if(delay)await pause(Math.min(delay,Math.max(0,budgetMs-(Date.now()-started))));
    try{event('asset','running','فحص مصدر JavaScript للأسرار والمراجع العامة',src);const asset=await fetchBounded(src,false,Infinity,true);if(!running())return;
     if(asset.status<200||asset.status>=300||!/(?:javascript|ecmascript|text\/plain)/i.test(asset.headers['content-type']??''))throw new Error(`HTTP ${asset.status}: لم تجمع استجابة JavaScript نصية ناجحة`);
     const a=analyze(asset);result.collection!.scriptSuccesses++;result.checks!.push(...a.checks.filter(c=>c.rule==='security.secret'||c.rule.startsWith('security.api-')));result.findings.push(...a.findings.filter(f=>f.rule==='security.secret'||f.rule==='security.api-reference-https'));mergeDiscovery(a);event('asset','done',`جُمع مصدر JavaScript • HTTP ${asset.status}`,src);
    }catch(e){event('asset','warning',e instanceof Error?e.message:'تعذر جلب المصدر',src);result.checks!.push({id:'security.secret|'+redact(src),rule:'security.secret',category:'security',status:'unavailable',weight:4,title:'فحص أنماط المفاتيح في مصدر JavaScript',url:redact(src),evidence:'لم يجمع المصدر بنجاح؛ لا يمكن اعتباره خاليًا من الأسرار.',recommendation:'راجع المصدر وسبب فشل جمعه.'});error(`تعذر جلب ${src}: ${e instanceof Error?e.message:'اتصال'}`);}
   }
  }catch(e){if(!running())return;crawl.failed++;event('fetch','warning',e instanceof Error?e.message:'خطأ اتصال',url);error(`تعذر جمع ${url}: ${e instanceof Error?e.message:'خطأ اتصال'}`);}
  publish(`جُمعت ${result.pages.length} صفحة • متبقٍ ${pending.size}`);if(delay)await pause(Math.min(delay,Math.max(0,budgetMs-(Date.now()-started))));
 }
 if(!running())return;syncCounts();
 crawl.stopReason??=Date.now()-started>=budgetMs?'time_limit':pending.size?'page_limit':crawl.discoveryLimited?'discovery_limit':'exhausted';
 if(crawl.stopReason!=='exhausted')error(`سبب توقف الزحف: ${crawl.stopReason}؛ متبقٍ ${pending.size} رابطًا معروفًا. قد توجد صفحات لم تُكتشف.`);
 event('analyze','running','فحص HTTP تلقائي لأصول API المكتشفة: HEAD/OPTIONS بلا حسابات أو قراءة موارد بيانات.');
 const automatic=await runAutomaticApiHttp(result.services,{running,budgetMs:Math.max(1,budgetMs-(Date.now()-started)),transport:options.apiHttpTransport,onCheck:(c,summary)=>{result.apiHttp=summary;const index=result.checks!.findIndex(old=>old.id===c.id);if(index>=0)result.checks![index]=c;else result.checks!.push(c);event('analyze',c.status==='unavailable'?'warning':'done',c.title+': '+(c.execution?.observed??c.evidence),c.url);}});
 result.apiHttp=automatic.summary;result.findings.push(...automatic.findings);if(automatic.summary.status==='partial')error('فحص HTTP للـAPI جزئي؛ راجع حالات الاتصال/المهلة.');if(!running())return;
 result.findings=[...new Map(result.findings.map(f=>[f.id,f])).values()];result.checks=[...new Map(result.checks!.map(c=>[c.rule==='security.api-discovery'||c.rule==='security.api-reference-https'||c.execution?.engine==='api-http/0.12'?c.id:c.url+'|'+c.rule,c])).values()];
 const status=!result.pages.length?'failed':result.errors.length?'partial':'completed';
 event('complete',status==='completed'?'done':'warning',`انتهى الزحف: ${result.pages.length} صفحات، ${discovered.size} روابط مكتشفة، ${pending.size} متبقية. السبب: ${crawl.stopReason}`);publish('انتهى جمع الروابط وتحليل الصفحات',true);
 store.finishScan(job.id,status,normalizeLegacyResult(result),!result.pages.length?'لم تُجمع صفحات HTML؛ لا يمكن استنتاج سلامة الموقع':null);
}
