import test from 'node:test';
import assert from 'node:assert/strict';
import {gzipSync,brotliCompressSync} from 'node:zlib';
import {decodeBody} from '../src/lib/network.ts';
import {resourcePolicy} from '../src/lib/resource-policy.ts';
test('decodes compressed responses and rejects decompression overflow',()=>{
 const body=Buffer.from('<html>محتوى</html>');assert.equal(decodeBody(gzipSync(body),'gzip').toString(),body.toString());assert.equal(decodeBody(brotliCompressSync(body),'br').toString(),body.toString());
 assert.throws(()=>decodeBody(gzipSync(Buffer.alloc(5000)), 'gzip',100));
});
test('browser resource policy denies writes, private URLs, external navigations and privileged keys',()=>{
 assert.throws(()=>resourcePolicy('https://example.com/save','POST',{},false,'https://example.com'));
 assert.throws(()=>resourcePolicy('http://127.0.0.1/','GET',{},false,'https://example.com'));
 assert.throws(()=>resourcePolicy('https://outside.example/','GET',{},true,'https://example.com'));
 assert.throws(()=>resourcePolicy('https://project.supabase.co/rest/v1/users','GET',{apikey:'sb_secret_abcdefghijklmnopqrstuvwxyz'},false,'https://example.com'));
 assert.doesNotThrow(()=>resourcePolicy('https://cdn.example/app.js?v=1','GET',{},false,'https://example.com'));
});
