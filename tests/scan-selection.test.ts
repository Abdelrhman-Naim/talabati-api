import test from 'node:test';
import assert from 'node:assert/strict';
import {selectedScan} from '../src/lib/scan-selection.ts';
import type {Scan} from '../src/lib/types';
test('activity selection resolves another project even when result filter is scoped',()=>{
 const a={id:'a',project_id:'A'},b={id:'b',project_id:'B'};const all=[a,b] as Scan[];
 assert.equal(selectedScan(all,'A','b',true),b);
 assert.equal(selectedScan(all,'A','b',false),a);
});
