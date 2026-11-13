import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {encrypt,decrypt,ready,b64,unb64} from '../web/crypto.mjs';
const s=await ready(), [mode,path]=process.argv.slice(2);
if(mode==='write'){
 await mkdir(path,{recursive:true});
 const box=s.crypto_box_keypair(), file=new File([new Uint8Array(70001).fill(65)],'interop ü.txt');
 const download=await encrypt(file),upload=await encrypt(file,box.publicKey);
 await writeFile(path+'/js-download.bin',new Uint8Array(await download.blob.arrayBuffer()));
 await writeFile(path+'/js-upload.bin',new Uint8Array(await upload.blob.arrayBuffer()));
 await writeFile(path+'/js-meta.json',JSON.stringify({key:b64(download.key),public:b64(box.publicKey),private:b64(box.privateKey)}));
}else{
 const meta=JSON.parse(await readFile(path+'/php-meta.json','utf8'));
 for(const kind of ['download','upload']){
  const result=await decrypt(new Uint8Array(await readFile(path+'/php-'+kind+'.bin')),kind==='download'?unb64(meta.key):null,{publicKey:unb64(meta.public),privateKey:unb64(meta.private)});
  if(result.name!=='interop ü.txt'||result.blob.size!==70001||await result.blob.text()!=='A'.repeat(70001))throw Error('PHP interoperability failure');
 }
 console.log('PHP ↔ JavaScript secretstream interoperability passed');
}
