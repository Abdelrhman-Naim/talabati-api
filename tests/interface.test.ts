import test from 'node:test';
import assert from 'node:assert/strict';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {previousComparable} from '../src/lib/comparison.ts';
import Modal from '../src/components/modal.tsx';
import ScoreDashboard from '../src/components/score-dashboard.tsx';
import CheckLedger from '../src/components/check-ledger.tsx';
import {SCORE_VERSION} from '../src/lib/scoring.ts';
import type {ScanResult,AuditCheck} from '../src/lib/types.ts';
import type {Scan} from '../src/lib/types.ts';
test('historical reports compare only with older same-project same-kind reports',()=>{
 const scans=[{id:'future',created_at:300,project_id:'p',is_demo:0,result:{},status:'completed'},{id:'current',created_at:200,project_id:'p',is_demo:0,result:{},status:'completed'},{id:'older',created_at:100,project_id:'p',is_demo:0,result:{},status:'completed'}] as Scan[];
 assert.equal(previousComparable(scans,scans[1])?.id,'older');assert.equal(previousComparable(scans,scans[2]),undefined);
});
test('a failed action appears inside the active dialog instead of behind its backdrop',()=>{
 const markup=renderToStaticMarkup(createElement(Modal,{title:'تحقق',error:'فشل التحقق',onClose:()=>{},children:createElement('p',null,'المحتوى')}));
 assert.ok(markup.includes('role="alert"'));assert.ok(markup.includes('فشل التحقق'));assert.ok(markup.indexOf('فشل التحقق')>markup.indexOf('role="dialog"'));
});
test('dashboard exposes calculated percentages, per-axis counts and coverage with a legacy rescan path',()=>{
 const checks:AuditCheck[]=[{id:'a',rule:'a',category:'seo',status:'pass',weight:2,title:'Title',evidence:'exists',url:'https://example.com',recommendation:'ok'},{id:'b',rule:'b',category:'seo',status:'fail',weight:1,title:'Description',evidence:'missing',url:'https://example.com',recommendation:'add'}];
 const result:ScanResult={checks,scoreVersion:SCORE_VERSION,findings:[],services:[],pages:[],coverage:[],errors:[],engine:'test',scope:'https://example.com'};
 const markup=renderToStaticMarkup(createElement(ScoreDashboard,{result,onCategory:()=>{},onRescan:()=>{}}));
 assert.ok(markup.includes('67%'));assert.ok(markup.includes('SEO'));assert.ok(markup.includes('GEO / AEO'));assert.ok(markup.includes('نجاح الفحوص المنفذة'));assert.ok(markup.includes('تغطية القواعد'));
 const legacy=renderToStaticMarkup(createElement(ScoreDashboard,{result:{...result,checks:undefined,scoreVersion:undefined},onCategory:()=>{},onRescan:()=>{}}));
 assert.ok(legacy.includes('إعادة الفحص'));assert.ok(!legacy.includes('100%'));assert.ok(!legacy.includes('axis-card'));
 const ledger=renderToStaticMarkup(createElement(CheckLedger,{checks,category:'all'}));assert.ok(ledger.includes('Title'));assert.ok(ledger.includes('ناجح'));assert.ok(ledger.includes('فاشل'));
});
test('activity shows actual warnings and never an invented percentage',async()=>{
 const {default:ScanActivity}=await import('../src/components/scan-activity.tsx');
 const scan={id:'live',status:'running',stage:'جمع الصفحة',updated_at:Date.now(),result:{pages:[],checks:[],findings:[],events:[{id:'1',at:Date.now(),phase:'fetch',status:'warning',message:'HTTP 404: https://example.com/missing'}]}} as unknown as Scan;
 const html=renderToStaticMarkup(createElement(ScanActivity,{scan,workerOnline:false,onResults:()=>{},onCancel:()=>{}}));
 assert.ok(html.includes('HTTP 404'));assert.ok(html.includes('العامل غير متصل'));assert.ok(!html.includes('%'));
});
test('unfinished scans cannot generate final report or whole-scan repair prompt in output center',async()=>{
 const {default:ScanOutputs}=await import('../src/components/scan-outputs.tsx');
 const scan={id:'running',status:'running',result:null} as Scan;
 const html=renderToStaticMarkup(createElement(ScanOutputs,{scan,projectName:'Test',preview:false,mode:'report',onMode:()=>{}}));
 assert.ok(html.includes('انتظر انتهاء الفحص'));assert.ok(/disabled=""[^>]*>.*?تجهيز تقرير الفحص/s.test(html));
});
test('a completed historical start is not displayed as the phase happening now',async()=>{
 const {default:ScanActivity}=await import('../src/components/scan-activity.tsx');
 const scan={id:'live',status:'running',stage:'تحليل انتهى',updated_at:Date.now(),result:{pages:[],checks:[],findings:[],events:[{id:'1',at:1,phase:'analyze',status:'running',message:'start',url:'https://example.com/old-current-marker'},{id:'2',at:2,phase:'analyze',status:'done',message:'done'}]}} as unknown as Scan;
 const html=renderToStaticMarkup(createElement(ScanActivity,{scan,workerOnline:true,onResults:()=>{},onCancel:()=>{}}));
 assert.ok(!html.slice(html.indexOf('class="activity-now"'),html.indexOf('class="activity-counts"')).includes('old-current-marker'));
});
test('crawl summary makes remaining URLs and the actual stop reason visible',async()=>{
 const {default:CrawlSummary}=await import('../src/components/crawl-summary.tsx');
 const result={pages:[],collection:{discovered:40},crawl:{mode:'full',maxPages:7,maxDurationMs:60000,remaining:33,failed:0,skipped:1,sitemaps:2,discoveryLimited:false,stopReason:'page_limit',skippedSamples:[],discoveryWarnings:[]}} as unknown as ScanResult;
 const html=renderToStaticMarkup(createElement(CrawlSummary,{result}));assert.ok(html.includes('وصل إلى حد الصفحات'));assert.ok(html.includes('33'));assert.ok(html.includes('لا يثبت اكتشاف كل صفحات'));
});
