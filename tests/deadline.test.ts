import test from 'node:test';
import assert from 'node:assert/strict';
import {withDeadline} from '../src/lib/deadline.ts';
test('deadline rejects stalled work even if closing its resource never resolves',async()=>{
 let closed=false;const start=Date.now();
 await assert.rejects(withDeadline(new Promise<never>(()=>{}),20,()=>{closed=true;return new Promise<void>(()=>{});}),/مهلة/);
 assert.equal(closed,true);assert.ok(Date.now()-start<1000);
});
