import test from 'node:test';
import assert from 'node:assert/strict';
import {encrypt,decrypt,ready,cipherSize,safeName} from '../web/crypto.mjs';
const sodium=await ready();
for(const size of [1,65536,65537,131072])test(`download roundtrip ${size}`,async()=>{
 const input=new File([new Uint8Array(size).fill(65)],'hello ü.txt');
 const result=await encrypt(input);
 assert.equal(result.blob.size,cipherSize(input));
 const plain=await decrypt(new Uint8Array(await result.blob.arrayBuffer()),result.key);
 assert.equal(plain.name,input.name);assert.deepEqual(new Uint8Array(await plain.blob.arrayBuffer()),new Uint8Array(await input.arrayBuffer()));
});
test('sealed inbox upload can only be opened by its inbox',async()=>{
 const box=sodium.crypto_box_keypair(), input=new File(['test upload'],'inbox.txt');
 const result=await encrypt(input,box.publicKey), data=new Uint8Array(await result.blob.arrayBuffer());
 assert.equal(result.blob.size,cipherSize(input,true));
 assert.equal(await (await decrypt(data,null,box)).blob.text(),'test upload');
 await assert.rejects(decrypt(data,null,sodium.crypto_box_keypair()));
});
test('tampering truncation appended bytes and wrong keys fail',async()=>{
 const {blob,key}=await encrypt(new File(['known plaintext'],'test.txt'));
 const bytes=new Uint8Array(await blob.arrayBuffer());
 for(const offset of [0,5,30,bytes.length-1]){const changed=bytes.slice();changed[offset]^=1;await assert.rejects(decrypt(changed,key));}
 for(const length of [0,20,bytes.length-1,bytes.length-21])await assert.rejects(decrypt(bytes.subarray(0,length),key));
 await assert.rejects(decrypt(new Uint8Array([...bytes,0]),key));
 await assert.rejects(decrypt(bytes,sodium.randombytes_buf(32)));
});
test('unsafe names and empty files fail before encryption',async()=>{
 for(const name of ['../x','a\\x','NUL.txt','.hidden','x\x00.txt','trailing.'])assert.throws(()=>safeName(name));
 await assert.rejects(encrypt(new File([],'empty.txt')));
});
