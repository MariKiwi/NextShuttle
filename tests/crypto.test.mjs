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

const {protect}=await import('../web/protection.mjs');
test('v2 downloads require password, share identity and supplied encryption key',async()=>{
 const id='1'.repeat(32),token='t'.repeat(43),seed=sodium.randombytes_buf(32),salt=sodium.randombytes_buf(16);
 const encode=x=>sodium.to_base64(x,sodium.base64_variants.URLSAFE_NO_PADDING);
 const binding=`D2.${id}.${token}.${encode(seed)}.${encode(salt)}`,password='a strong encryption password';
 const protection=await protect(binding,password),result=await encrypt(new File(['protected content'],'protected.txt'),null,protection),data=new Uint8Array(await result.blob.arrayBuffer());
 assert.equal(result.blob.size,cipherSize(new File(['protected content'],'protected.txt'),false,true));
 assert.equal(await (await decrypt(data,seed,null,protection)).blob.text(),'protected content');
 await assert.rejects(decrypt(data,seed));
 for(const changed of [await protect(binding,'the wrong long password'),await protect(binding.replace(id,'2'.repeat(32)),password),await protect(binding.replace(encode(seed),encode(sodium.randombytes_buf(32))),password)]){
  assert.notEqual(changed.authorization,protection.authorization);await assert.rejects(decrypt(data,seed,null,changed));
 }
 const legacy=await encrypt(new File(['legacy'],'legacy.txt'));await assert.rejects(decrypt(new Uint8Array(await legacy.blob.arrayBuffer()),legacy.key,null,protection));
});
test('v2 uploads require the inbox private key AND the password',async()=>{
 const box=sodium.crypto_box_keypair(),encode=x=>sodium.to_base64(x,sodium.base64_variants.URLSAFE_NO_PADDING);
 const binding=`U2.${'3'.repeat(32)}.${encode(box.publicKey)}.${encode(sodium.randombytes_buf(16))}`,protection=await protect(binding,'a strong inbox encryption password');
 const file=new File(['protected upload'],'upload.txt'),result=await encrypt(file,box.publicKey,protection),data=new Uint8Array(await result.blob.arrayBuffer());
 assert.equal(result.blob.size,cipherSize(file,true,true));assert.equal(await (await decrypt(data,null,box,protection)).blob.text(),'protected upload');
 await assert.rejects(decrypt(data,null,box));await assert.rejects(decrypt(data,null,sodium.crypto_box_keypair(),protection));
 await assert.rejects(decrypt(data,null,box,await protect(binding,'a different long password')));
 for(const offset of [5,22,data.length-1]){const tampered=data.slice();tampered[offset]^=1;await assert.rejects(decrypt(tampered,null,box,protection));}
});
