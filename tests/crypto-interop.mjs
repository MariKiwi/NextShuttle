import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {encrypt,decrypt,ready,b64,unb64} from '../web/crypto.mjs';
import {protect} from '../web/protection.mjs';
const s=await ready(), [mode,path]=process.argv.slice(2);
if(mode==='write'){
 await mkdir(path,{recursive:true});
 const box=s.crypto_box_keypair(), file=new File([new Uint8Array(70001).fill(65)],'interop ü.txt');
 const download=await encrypt(file),upload=await encrypt(file,box.publicKey);
 await writeFile(path+'/js-download.bin',new Uint8Array(await download.blob.arrayBuffer()));
 await writeFile(path+'/js-upload.bin',new Uint8Array(await upload.blob.arrayBuffer()));
 await writeFile(path+'/js-meta.json',JSON.stringify({key:b64(download.key),public:b64(box.publicKey),private:b64(box.privateKey)}));
 const v2={};
 for(const kind of ['download','upload']){
  const box=s.crypto_box_keypair(),seed=s.randombytes_buf(32),salt=b64(s.randombytes_buf(16)),id='8'.repeat(32),password='a long interop encryption password',binding=kind==='download'?`D2.${id}.${'t'.repeat(43)}.${b64(seed)}.${salt}`:`U2.${id}.${b64(box.publicKey)}.${salt}`;
  const protection=await protect(binding,password),result=await encrypt(new File(['protected interop'],'protected.txt'),kind==='upload'?box.publicKey:null,protection);
  v2[kind]={binding,password,id,salt,seed:b64(seed),public:b64(box.publicKey),private:b64(box.privateKey),authorization:protection.authorization};
  await writeFile(path+'/js-v2-'+kind+'.bin',new Uint8Array(await result.blob.arrayBuffer()));
 }
 await writeFile(path+'/v2-meta.json',JSON.stringify(v2));
}else{
 const meta=JSON.parse(await readFile(path+'/php-meta.json','utf8'));
 for(const kind of ['download','upload']){
  const result=await decrypt(new Uint8Array(await readFile(path+'/php-'+kind+'.bin')),kind==='download'?unb64(meta.key):null,{publicKey:unb64(meta.public),privateKey:unb64(meta.private)});
  if(result.name!=='interop ü.txt'||result.blob.size!==70001||await result.blob.text()!=='A'.repeat(70001))throw Error('PHP interoperability failure');
 }
 const v2=JSON.parse(await readFile(path+'/v2-meta.json','utf8'));
 for(const kind of ['download','upload']){
  const v=v2[kind],protection=await protect(v.binding,v.password),box={publicKey:unb64(v.public),privateKey:unb64(v.private)};
  const result=await decrypt(new Uint8Array(await readFile(path+'/php-v2-'+kind+'.bin')),unb64(v.seed),box,protection);
  if(result.name!=='protected.txt'||await result.blob.text()!=='protected interop')throw Error('Protected PHP decryption failed');
 }
 console.log('PHP ↔ JavaScript secretstream interoperability passed');
}
