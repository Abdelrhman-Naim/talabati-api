import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeCrawlUrl,parseRobots,parseSitemap,resolveCrawlOptions} from '../src/lib/crawler.ts';
import {analyze} from '../src/lib/audit.ts';
import {Store} from '../src/lib/db.ts';
import {runJob} from '../src/lib/jobs.ts';
import type {HttpPage} from '../src/lib/types';
const origin='https://example.com';
function page(url:string,body:string,status=200,type='text/html'):HttpPage{return {url,body,status,headers:{'content-type':type},bytes:body.length,elapsedMs:1};}
test('all internal links survive discovery and pagination queries retain content identity',()=>{
 const html=Array.from({length:40},(_,i)=>`<a href="/course/${i}">${i}</a>`).join('')+'<a href="/courses?page=2&utm_source=x#top">Next</a>';
 const links=analyze(page(origin+'/',html)).links;
 assert.equal(links.length,41);assert.ok(links.includes(origin+'/courses?page=2'));
 assert.equal(normalizeCrawlUrl('/courses?b=2&a=1&utm_source=x#top',origin+'/',origin),origin+'/courses?a=1&b=2');
 for(const url of ['https://outside.com/a','http://127.0.0.1/a','/delete/account','/image.png','/?token=private','/logout'])assert.equal(normalizeCrawlUrl(url,origin+'/',origin),null);
});
test('robots matches specific agent groups and longest allow/disallow paths',()=>{
 const r=parseRobots('User-agent: *\nDisallow: /all\nUser-agent: AegisAuditBeta\nDisallow: /private\nAllow: /private/public\nDisallow: /*?secret=*\nSitemap: https://example.com/index.xml');
 assert.equal(r.allowed(origin+'/private/x'),false);assert.equal(r.allowed(origin+'/private/public/x'),true);
 assert.equal(r.allowed(origin+'/all'),true);assert.equal(r.allowed(origin+'/a?secret=x'),false);assert.deepEqual(r.sitemaps,[origin+'/index.xml']);
});
test('sitemap parser distinguishes indexes, pages and escaped query strings',()=>{
 assert.deepEqual(parseSitemap('<sitemapindex><sitemap><loc>https://example.com/child.xml</loc></sitemap></sitemapindex>'),{kind:'index',urls:[origin+'/child.xml']});
 assert.deepEqual(parseSitemap('<urlset><url><loc>https://example.com/?page=2&amp;lang=ar</loc></url></urlset>').urls,[origin+'/?page=2&lang=ar']);
 assert.equal(parseSitemap('<html>not a map</html>').kind,'invalid');
});
test('full mode ignores old five-page quick limits while quick mode remains available',()=>{
 const old=process.env.MAX_SCAN_PAGES;process.env.MAX_SCAN_PAGES='5';
 try{assert.ok(resolveCrawlOptions({mode:'full'}).maxPages>25);assert.equal(resolveCrawlOptions({mode:'quick'}).maxPages,5);}finally{if(old===undefined)delete process.env.MAX_SCAN_PAGES;else process.env.MAX_SCAN_PAGES=old;}
});
test('full crawl visits >5 pages and recursively discovers sitemap-only and paginated pages',async()=>{
 const s=new Store(':memory:'),u=s.createUser('crawl@example.com','hash'),p=s.createProject(u.id,'Crawl',origin+'/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'full'});const job=s.claimJob()!;const calls:string[]=[];
 const fetch=async(url:string)=>{calls.push(url);
  if(url.endsWith('/robots.txt'))return page(url,'User-agent: *\nDisallow: /private\nSitemap: https://example.com/index.xml',200,'text/plain');
  if(url.endsWith('/index.xml'))return page(url,'<sitemapindex><sitemap><loc>https://example.com/map.xml</loc></sitemap><sitemap><loc>https://example.com/index.xml</loc></sitemap></sitemapindex>',200,'application/xml');
  if(url.endsWith('/map.xml'))return page(url,'<urlset><url><loc>https://example.com/orphan</loc></url><url><loc>https://outside.com/no</loc></url><url><loc>https://example.com/private</loc></url></urlset>',200,'application/xml');
  if(url.endsWith('/sitemap.xml'))return page(url,'missing',404);
  if(url===origin+'/')return page(url,Array.from({length:35},(_,i)=>`<a href="/p/${i}">page</a>`).join('')+'<a href="/list?page=2&utm_source=x">next</a>');
  return page(url,'<h1>page</h1>');
 };
 await runJob(s,job,fetch,0,{budgetMs:5000,fetchDiscovery:fetch});
 const done=s.ownedScan(u.id,job.id)!,r=done.result!;assert.equal(r.pages.length,38);assert.ok(r.pages.some(p=>p.url.endsWith('/orphan')));assert.equal(r.crawl?.remaining,0);assert.equal(r.crawl?.stopReason,'exhausted');
 assert.ok(!calls.some(x=>x.includes('outside.com')||x.endsWith('/private')));assert.ok(r.crawl!.skipped>0);s.close();
});
test('empty robots directives still end an agent group and cannot inherit another bot rules',()=>{
 const robots=parseRobots('User-agent: *\nDisallow:\n\nUser-agent: OtherBot\nDisallow: /');
 assert.equal(robots.allowed(origin+'/public'),true);
});
test('robots wildcard matching treats URI unicode consistently without regex backtracking',()=>{
 const robots=parseRobots('User-agent: *\nDisallow: /دورات\nDisallow: /*a*a*a*a*a*a*a*a*a*a*b$');
 assert.equal(robots.allowed(origin+'/'+encodeURIComponent('دورات')+'/1'),false);
 assert.equal(robots.allowed(origin+'/'+'a'.repeat(50)),true);
});
test('cancel during discovery aborts active work and never launches further sitemap/page requests',async()=>{
 const s=new Store(':memory:'),u=s.createUser('cancel-crawl@example.com','hash'),p=s.createProject(u.id,'Crawl',origin+'/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'full'});const job=s.claimJob()!;let calls=0,aborted=false;
 const fetch=async(_url:string,_origin?:string,signal?:AbortSignal)=>{calls++;signal?.addEventListener('abort',()=>{aborted=true;});setTimeout(()=>s.cancelScan(u.id,job.id),5);return new Promise<HttpPage>(()=>{});};
 const start=Date.now();await runJob(s,job,fetch,0,{budgetMs:1500,fetchDiscovery:fetch});
 assert.ok(Date.now()-start<1000);assert.equal(aborted,true);assert.equal(calls,1);assert.equal(s.ownedScan(u.id,job.id)?.status,'cancelled');assert.ok(!s.ownedScan(u.id,job.id)?.result?.events?.some(e=>e.phase==='complete'));s.close();
});
test('gzip sitemap bodies are decoded with the same decompression bounds',async()=>{
 const {gzipSync}=await import('node:zlib');
 assert.deepEqual(parseSitemap(gzipSync(Buffer.from('<urlset><url><loc>https://example.com/gzip-only</loc></url></urlset>'))).urls,[origin+'/gzip-only']);
});
test('page cap keeps known remaining links visible and marks the result partial',async()=>{
 const s=new Store(':memory:'),u=s.createUser('limit@example.com','hash'),p=s.createProject(u.id,'Crawl',origin+'/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'full',maxPages:7});const job=s.claimJob()!;
 const fetch=async(url:string)=>url.endsWith('.xml')||url.endsWith('robots.txt')?page(url,'missing',404):page(url,url===origin+'/'?Array.from({length:10},(_,i)=>`<a href="/p/${i}">p</a>`).join(''):'<h1>page</h1>');
 await runJob(s,job,fetch,0,{fetchDiscovery:fetch});const done=s.ownedScan(u.id,job.id)!;
 assert.equal(done.result?.pages.length,7);assert.equal(done.result?.crawl?.remaining,4);assert.equal(done.result?.crawl?.stopReason,'page_limit');assert.equal(done.status,'partial');s.close();
});
test('a larger site resolves HTML base links and relative child maps without losing pages',async()=>{
 const s=new Store(':memory:'),u=s.createUser('large@example.com','hash'),p=s.createProject(u.id,'Large',origin+'/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'full'});const job=s.claimJob()!;const calls:string[]=[];
 const fetch=async(url:string)=>{calls.push(url);
  if(url.endsWith('/robots.txt'))return page(url,'User-agent: *\nSitemap: https://example.com/maps/index.xml',200,'text/plain');
  if(url.endsWith('/maps/index.xml'))return page(url,'<sitemapindex><sitemap><loc>child.xml</loc></sitemap></sitemapindex>',200,'application/xml');
  if(url.endsWith('/maps/child.xml'))return page(url,'<urlset><url><loc>https://example.com/orphan-from-map</loc></url></urlset>',200,'application/xml');
  if(url===origin+'/')return page(url,'<base href="/app/">'+Array.from({length:120},(_,i)=>`<a href="p/${i}?utm_source=menu">p</a>`).join(''));
  if(url.startsWith(origin+'/app/p/')||url.endsWith('/orphan-from-map'))return page(url,'<h1>Found</h1>');
  return page(url,'missing',404);
 };
 try{await runJob(s,job,fetch,0,{fetchDiscovery:fetch,budgetMs:10000});const r=s.ownedScan(u.id,job.id)!.result!;
  assert.ok(calls.includes(origin+'/app/p/119'));assert.ok(calls.includes(origin+'/maps/child.xml'));
  assert.equal(r.pages.length,122);assert.equal(r.crawl?.failed,0);assert.equal(r.crawl?.remaining,0);
 }finally{s.close();}
});
test('an external HTML base never turns external relative links into local crawl targets',()=>{
 const output=analyze(page(origin+'/', '<base href="https://outside.com/path/"><a href="course">Course</a><script src="app.js"></script>'));
 assert.deepEqual(output.links,[]);assert.deepEqual(output.scripts,[]);
});
test('missing explicitly declared sitemaps mark discovery incomplete unlike optional candidates',async()=>{
 const s=new Store(':memory:'),u=s.createUser('missing-map@example.com','hash'),p=s.createProject(u.id,'Crawl',origin+'/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'full'});const job=s.claimJob()!;
 const fetch=async(url:string)=>url.endsWith('/robots.txt')?page(url,'Sitemap: https://example.com/declared.xml',200,'text/plain'):url===origin+'/'?page(url,'<h1>Root</h1>'):page(url,'missing',404);
 try{await runJob(s,job,fetch,0,{fetchDiscovery:fetch});const r=s.ownedScan(u.id,job.id)!.result!;assert.equal(r.crawl?.discoveryLimited,true);assert.equal(r.crawl?.stopReason,'discovery_limit');assert.ok(r.crawl?.discoveryWarnings.some(w=>w.includes('declared.xml')&&w.includes('404')));}finally{s.close();}
});
test('relative child sitemap resolves against its final URL after a same-origin redirect',async()=>{
 const s=new Store(':memory:'),u=s.createUser('redirect-map@example.com','hash'),p=s.createProject(u.id,'Crawl',origin+'/');s.verifyProject(u.id,p.id);s.queueScan(u.id,p.id,{mode:'full'});const job=s.claimJob()!;const calls:string[]=[];
 const fetch=async(url:string)=>{calls.push(url);if(url.endsWith('/robots.txt'))return page(url,'Sitemap: https://example.com/sitemap.xml',200,'text/plain');
  if(url.endsWith('/sitemap.xml'))return page(origin+'/maps/index.xml','<sitemapindex><sitemap><loc>child.xml</loc></sitemap></sitemapindex>',200,'application/xml');
  if(url.endsWith('/maps/child.xml'))return page(url,'<urlset><url><loc>../from-map</loc></url></urlset>',200,'application/xml');
  return url===origin+'/'||url.endsWith('/from-map')?page(url,'<h1>Page</h1>'):page(url,'missing',404);
 };
 try{await runJob(s,job,fetch,0,{fetchDiscovery:fetch});assert.ok(calls.includes(origin+'/maps/child.xml'));assert.ok(s.ownedScan(u.id,job.id)?.result?.pages.some(p=>p.url===origin+'/from-map'));}finally{s.close();}
});
