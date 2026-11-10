import test from 'node:test';
import assert from 'node:assert/strict';
import {summarizeChecks,scoreReport,SCORE_VERSION} from '../src/lib/scoring.ts';
import type {AuditCheck} from '../src/lib/types.ts';
import {markdownReport} from '../src/lib/prompts.ts';
import type {Scan} from '../src/lib/types.ts';
const c=(id:string,status:AuditCheck['status'],weight=1):AuditCheck=>({id,rule:id,category:'seo',status,weight,title:id,url:'https://example.com/',evidence:'observed',recommendation:'fix'});
test('score uses performed weighted outcomes, not number of issues or presence of results',()=>{
 const s=summarizeChecks([c('a','pass',2),c('b','fail',1),c('c','unavailable',9),c('d','not_applicable',20)]);
 assert.equal(s.overall.score,67);assert.equal(s.overall.coverage,67);assert.equal(s.overall.passed,1);assert.equal(s.overall.failed,1);assert.equal(s.overall.unavailable,1);assert.equal(s.overall.notApplicable,1);
});
test('empty, unavailable-only and legacy records never report a perfect score',()=>{
 assert.equal(summarizeChecks([]).overall.score,null);assert.equal(summarizeChecks([c('a','unavailable')]).overall.score,null);
 assert.equal(scoreReport({findings:[],coverage:[],pages:[],services:[],errors:[],scope:'https://example.com',engine:'old'}).legacy,true);
 assert.equal(scoreReport({scoreVersion:SCORE_VERSION,checks:[],findings:[],coverage:[],pages:[],services:[],errors:[],scope:'https://example.com',engine:'new'}).overall.score,null);
});
test('failed and passed pages both contribute to their category score',()=>{
 const checks=[c('p1','pass'),{...c('p2','fail'),url:'https://example.com/other'}];assert.equal(summarizeChecks(checks).categories.find(c=>c.id==='seo')?.score,50);
});
test('Markdown export contains the same calculated percentages and counts as the dashboard',()=>{
 const scan={status:'completed',is_demo:0,result:{checks:[c('a','pass',2),c('b','fail')],scoreVersion:SCORE_VERSION,findings:[],coverage:[],pages:[],services:[],errors:[],scope:'https://example.com',engine:'test'}} as unknown as Scan;
 assert.ok(markdownReport(scan).includes('67%'));assert.ok(markdownReport(scan).includes('SEO'));assert.ok(markdownReport(scan).includes('نجاح الفحوص'));
});
test('pages collected without any check records are an invalid legacy pipeline, not a normal 0/0 report',()=>{
 const summary=scoreReport({findings:[],coverage:[],pages:[{url:'https://example.com',status:200,bytes:1000,elapsedMs:2358}],services:[],errors:[],scope:'https://example.com',engine:'old-worker',scoreVersion:SCORE_VERSION,checks:[]});
 assert.equal(summary.legacy,true);assert.equal(summary.overall.score,null);
});
