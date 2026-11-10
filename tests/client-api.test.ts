import test from 'node:test';
import assert from 'node:assert/strict';
import {api,ApiError} from '../src/lib/client-api.ts';
test('HTML 404 responses identify endpoint and status instead of failing JSON parsing',async()=>{
 const original=globalThis.fetch;globalThis.fetch=async()=>new Response('<html>not found</html>',{status:404,headers:{'content-type':'text/html'}});
 try{await assert.rejects(api('state'),(e:unknown)=>e instanceof ApiError&&e.status===404&&e.message.includes('/api/state')&&e.message.includes('404'));}finally{globalThis.fetch=original;}
});
