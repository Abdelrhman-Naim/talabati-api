import test from 'node:test';
import assert from 'node:assert/strict';
import {collect} from '../src/lib/network.ts';
import type {HttpPage} from '../src/lib/types';
const root='https://example.com/';
const response=(url:string):HttpPage=>({url,status:302,headers:{location:'/private'},body:'',bytes:0,elapsedMs:1});
test('redirect destination is checked before a second transport request',async()=>{
 const calls:string[]=[];
 await assert.rejects(collect(root,undefined,0,{transport:async url=>{calls.push(url);return response(url);},allowUrl:url=>!url.endsWith('/private')}),/سياسة/);
 assert.deepEqual(calls,[root]);
});
test('aborting a redirect response prevents the next request',async()=>{
 const calls:string[]=[],controller=new AbortController();
 await assert.rejects(collect(root,undefined,0,{signal:controller.signal,transport:async url=>{calls.push(url);controller.abort(new Error('cancelled-test'));return response(url);}}),/cancelled-test/);
 assert.deepEqual(calls,[root]);
});
