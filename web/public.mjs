import {protect} from './protection.mjs';
import {ready,unb64,encrypt,decrypt,cipherSize,MAX_CIPHER} from './crypto.mjs';
const $=id=>document.getElementById(id), status=$('status'), form=$('transfer-form');
const say=text=>{status.textContent=text;};
function consumeHash(){if(!location.hash)return;try{$('code').value=decodeURIComponent(location.hash.slice(1));$('password').value='';$('key').value='';$('file').value='';$('result').replaceChildren();say('Files are encrypted before upload and decrypted on your device.');}catch{say('Invalid transfer code');}history.replaceState(null,'',location.pathname);$('code').dispatchEvent(new Event('input'));recordView();}
window.addEventListener('hashchange',consumeHash);
function parse(){
 let value=$('code').value.trim();if(value.startsWith('http')){const link=new URL(value);if(link.origin!==location.origin||link.pathname!==location.pathname)throw Error('Use a NextShuttle link from this site');value=decodeURIComponent(link.hash.slice(1));}
 const parts=value.split('.');
 if(!/^[a-f0-9]{32}$/.test(parts[1]??''))throw Error('Enter a complete NextShuttle code');
 if(parts[0]==='D2'){
  if(parts.length===4)parts.splice(3,0,$('key').value.trim());
  if(parts.length===5&&/^[A-Za-z0-9_-]{43}$/.test(parts[2])&&unb64(parts[3]).length===32&&unb64(parts[4]).length===16)return {kind:'D',version:2,id:parts[1],token:parts[2],key:unb64(parts[3]),binding:parts.join('.')};
 }
 if(parts[0]==='U2'){
  if(parts.length===3)parts.splice(2,0,$('key').value.trim());
  if(parts.length===4&&unb64(parts[2]).length===32&&unb64(parts[3]).length===16)return {kind:'U',version:2,id:parts[1],public:unb64(parts[2]),binding:parts.join('.')};
 }
 if(parts[0]==='D'&&parts.length===4&&/^[A-Za-z0-9_-]{43}$/.test(parts[2])&&unb64(parts[3]).length===32)return {kind:'D',id:parts[1],token:parts[2],key:unb64(parts[3])};
 if(parts[0]==='U'&&parts.length===3&&unb64(parts[2]).length===32)return {kind:'U',id:parts[1],public:unb64(parts[2])};
 throw Error('Enter a complete NextShuttle code');
}
async function bounded(response){
 if(!response.ok)throw Error('Code invalid, expired, exhausted or transfer unavailable');
 const reader=response.body.getReader(),chunks=[];let length=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>MAX_CIPHER)throw Error('Encrypted file exceeds the safety limit');chunks.push(value);}}
 catch(error){await reader.cancel();throw error;}
 const bytes=new Uint8Array(length);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}return bytes;
}
form.addEventListener('submit',async event=>{
 event.preventDefault();$('submit').disabled=true;let protection=null;
 try{
  const sodium=await ready(),code=parse();
  if(code.version===2){say('Unlocking encryption locally…');await new Promise(resolve=>setTimeout(resolve,25));protection=await protect(code.binding,$('password').value);}
  if(code.kind==='D'){
   say('Retrieving encrypted file…');
   const password=protection?protection.authorization:$('password').value;
   const response=await fetch(`./api/v1/downloads/${code.id}/fetch`,{method:'POST',headers:{Authorization:'Bearer '+code.token,...(password?{'Content-Type':'application/json'}:{})},body:password?JSON.stringify({password}):'',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});
   const result=await decrypt(await bounded(response),code.key,null,protection);
   const url=URL.createObjectURL(result.blob),link=document.createElement('a');link.href=url;link.download=result.name;link.textContent='Save '+result.name;
   $('result').replaceChildren(link);link.click();setTimeout(()=>URL.revokeObjectURL(url),60000);say('Decrypted locally. Save the file to finish.');sodium.memzero(code.key);
  }else{
   const file=$('file').files[0],password=protection?protection.authorization:$('password').value;
   if(!file||password.length<16)throw Error('Choose a file and enter the upload password');
   const bytes=cipherSize(file,true,Boolean(protection));if(bytes>MAX_CIPHER)throw Error('File exceeds the upload limit');
   say('Authorizing upload…');
   const response=await fetch(`./api/v1/inboxes/${code.id}/uploads`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password,bytes}),credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer'});
   if(!response.ok)throw Error('Upload code/password invalid, inbox closed, or quota reached');
   const reservation=await response.json();
   if(!/^[a-f0-9]{32}$/.test(reservation.id)||!/^[A-Za-z0-9_-]{43}$/.test(reservation.upload_token))throw Error('Invalid upload authorization');
   const reported=sodium.from_base64(reservation.public_key,sodium.base64_variants.ORIGINAL);
   if(!sodium.memcmp(reported,code.public))throw Error('Inbox encryption key does not match the trusted code');
   say('Encrypting locally…');const result=await encrypt(file,code.public,protection);sodium.memzero(result.key);
   say('Sending encrypted file…');
   const sent=await fetch(`./api/v1/uploads/${reservation.id}/blob`,{method:'PUT',headers:{Authorization:'Bearer '+reservation.upload_token,'Content-Type':'application/octet-stream'},body:result.blob,credentials:'omit',referrerPolicy:'no-referrer'});
   if(!sent.ok)throw Error('Encrypted upload did not finish. The inbox may have closed.');
   $('file').value='';$('password').value='';say('Encrypted upload received. Private validation and malware scanning must finish before import.');
  }
 }catch(error){say(error.message||'Transfer failed');}
 finally{if(protection)(await ready()).memzero(protection.root);$('submit').disabled=false;}
});
$('code').addEventListener('input',()=>{const upload=$('code').value.trim().match(/(?:^|#)U2?\./);$('upload-fields').hidden=!upload;$('submit').textContent=upload?'Encrypt and upload':'Decrypt and download';});
$('code').dispatchEvent(new Event('input'));
async function recordView(){try{const sodium=await ready(),code=parse();if(code.kind==='D')await fetch(`./api/v1/downloads/${code.id}/view`,{method:'POST',headers:{Authorization:'Bearer '+code.token},body:'',credentials:'omit',referrerPolicy:'no-referrer'});else await fetch(`./api/v1/inboxes/${code.id}/view`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({public_key:sodium.to_base64(code.public,sodium.base64_variants.ORIGINAL)}),credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer'});}catch{}}
$('code').addEventListener('change',recordView);if(location.hash)consumeHash();else recordView();

$('key').addEventListener('change',recordView);
