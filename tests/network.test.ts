import test from 'node:test';
import assert from 'node:assert/strict';
import {validateTarget, assertPublicAddress, assertResolved, redact, pinnedLookup} from '../src/lib/network.ts';

test('rejects private, mapped, metadata, loopback and numeric-encoded targets',()=>{
  for(const ip of ['127.0.0.1','10.0.0.1','169.254.169.254','192.168.2.1','100.64.0.1','0.0.0.0','::1','::ffff:127.0.0.1','fc00::1','fe80::1','2001:db8::1']) assert.throws(()=>assertPublicAddress(ip));
  assert.throws(()=>validateTarget('http://2130706433/'));
  assert.doesNotThrow(()=>assertPublicAddress('8.8.8.8'));
  assert.doesNotThrow(()=>assertPublicAddress('2606:4700:4700::1111'));
});
test('rejects credentials, local names, non-web protocols and arbitrary ports',()=>{
  for(const u of ['file:///etc/passwd','http://localhost','http://a.local','https://u:p@example.com','https://example.com:8443']) assert.throws(()=>validateTarget(u));
  assert.equal(validateTarget('https://example.com/path#hello').hash,'');
});
test('rejects secret-bearing target paths before they can be persisted as project URLs',()=>{
  assert.throws(()=>validateTarget('https://example.com/sk_live_abcdefghijklmnop'),/سر/);
  assert.throws(()=>validateTarget('https://example.com/sb_secret_abcdefghijklmnop'),/سر/);
});
test('mixed DNS answers are rejected, not filtered into apparent safety',()=>{
  assert.throws(()=>assertResolved([{address:'8.8.8.8',family:4},{address:'10.0.0.1',family:4}]));
  assert.throws(()=>assertResolved([]));
});
test('pinned DNS lookup supports Node autoSelectFamily all-address contract',()=>{
  const lookup=pinnedLookup({address:'8.8.8.8',family:4});
  lookup('example.com',{all:true},(_error:unknown,addresses:unknown)=>assert.deepEqual(addresses,[{address:'8.8.8.8',family:4}]));
  lookup('example.com',{},(_error:unknown,address:unknown,family?:number)=>{assert.equal(address,'8.8.8.8');assert.equal(family,4);});
});
test('redacts privileged keys, bearer tokens and URL credentials before evidence persistence',()=>{
  const value=redact('sb_secret_abcdefghijklmnopqrstuvwxyz Authorization: Bearer abcdefghijklmnop https://user:pass@example.com/path?api_key=abcdefghij');
  assert.ok(!value.includes('abcdefghijklmnopqrstuvwxyz'));
  assert.ok(!value.includes('abcdefghijklmnop'));
  assert.ok(!value.includes('user:pass'));
  assert.ok(!value.includes('abcdefghij'));
});
test('discovered session and CSRF URLs are redacted before reports',()=>{
 assert.ok(!redact('https://example.com/?sessionid=private-session&csrf=private-csrf').includes('private-session'));
 assert.ok(!redact('https://example.com/?sessionid=private-session&csrf=private-csrf').includes('private-csrf'));
});
