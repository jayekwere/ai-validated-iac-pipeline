import {test} from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import {activeScannerExceptions,MAX_EXCEPTION_DAYS} from '../src/exceptions.ts';

const now=new Date('2026-11-01T12:00:00Z');
const entry={id:'AWS-0132',resource:'aws_s3_bucket_server_side_encryption_configuration.logs',reason:'ALB access logs cannot be written to SSE-KMS buckets.',source:'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html',expires:'2027-05-01'};
const doc=(...exceptions:unknown[])=>({version:'1.0.0',exceptions});

test('committed scanner exceptions are well formed and unexpired',()=>{assert.ok(activeScannerExceptions(JSON.parse(readFileSync('policy/scanner-exceptions.json','utf8'))).length>0);});
test('active exception is returned',()=>assert.deepEqual(activeScannerExceptions(doc(entry),now),[entry]));
test('exception expiring today is still active',()=>assert.equal(activeScannerExceptions(doc({...entry,expires:'2026-11-01'}),now).length,1));
test('expired exception fails the gate',()=>assert.throws(()=>activeScannerExceptions(doc({...entry,expires:'2026-10-31'}),now),/EXCEPTION_EXPIRED: AWS-0132/));
test('exception longer than the review window is rejected',()=>{
  const limit=new Date(now.getTime()+MAX_EXCEPTION_DAYS*86_400_000).toISOString().slice(0,10);
  assert.equal(activeScannerExceptions(doc({...entry,expires:limit}),now).length,1);
  assert.throws(()=>activeScannerExceptions(doc({...entry,expires:'2099-01-01'}),now),/EXCEPTION_TOO_LONG/);
});
test('missing expiry is rejected',()=>{const {expires,...rest}=entry;assert.throws(()=>activeScannerExceptions(doc(rest),now),/EXCEPTION_FORMAT/);});
for(const expires of ['2027-02-30','2027-5-1','tomorrow','']) test('invalid expiry '+JSON.stringify(expires)+' is rejected',()=>assert.throws(()=>activeScannerExceptions(doc({...entry,expires}),now),/EXCEPTION_FORMAT/));
test('unknown fields are rejected',()=>assert.throws(()=>activeScannerExceptions(doc({...entry,severity:'LOW'}),now),/EXCEPTION_FORMAT/));
test('non https source is rejected',()=>assert.throws(()=>activeScannerExceptions(doc({...entry,source:'http://example.com'}),now),/EXCEPTION_FORMAT/));
test('wildcard or malformed check ID is rejected',()=>{for(const id of ['*','AWS-*','aws-0132'])assert.throws(()=>activeScannerExceptions(doc({...entry,id}),now),/EXCEPTION_FORMAT/);});
test('duplicate exception is rejected',()=>assert.throws(()=>activeScannerExceptions(doc(entry,{...entry}),now),/EXCEPTION_DUPLICATE/));
for(const value of [null,{},{exceptions:{}},[entry]]) test('malformed document '+JSON.stringify(value)?.slice(0,30)+' is rejected',()=>assert.throws(()=>activeScannerExceptions(value,now),/EXCEPTIONS?_FORMAT/));
