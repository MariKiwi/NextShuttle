import {getRequestToken} from '@nextcloud/auth';
import {generateUrl} from '@nextcloud/router';
export async function api(path='',body=null){
 const response=await fetch(generateUrl('/apps/nextshuttle/'+path),{method:body===null?'GET':'POST',credentials:'same-origin',cache:'no-store',headers:{requesttoken:getRequestToken(),'Content-Type':'application/json'},body:body===null?null:JSON.stringify(body)});
 const data=await response.json();if(!response.ok)throw Error(data.error||'NextShuttle request failed');return data;
}
export function button(label,callback){const b=document.createElement('button');b.type='button';b.textContent=label;b.addEventListener('click',callback);return b;}
export async function openTransfer(node){
 const kind=node.type==='folder'?'inbox':'download',dialog=document.createElement('dialog');dialog.className='ns-dialog';
 const title=document.createElement('h2');title.textContent=kind==='inbox'?'Receive files with NextShuttle':'Share with NextShuttle';
 const name=document.createElement('p');name.textContent=node.basename||node.displayname||'Selected item';
 const form=document.createElement('form'),status=document.createElement('p');status.role='status';
 const limits=(await api('transfers')).policy;
 function field(label,type,value,min,max){const l=document.createElement('label');l.textContent=label;const i=document.createElement('input');i.type=type;i.value=value;if(min!==undefined)i.min=min;if(max!==undefined)i.max=max;i.required=true;l.append(i);form.append(l);return i;}
 const hours=field('Available for (hours)','number',Math.max(1,limits.default_ttl/3600),1/60,limits.max_ttl/3600);hours.step='any';
 const uses=field(kind==='inbox'?'Maximum files':'Maximum downloads','number',kind==='inbox'?limits.max_inbox_files:1,1,kind==='inbox'?limits.max_inbox_files:limits.max_downloads);
 let password,bytes;
 password=field(kind==='inbox'?`Reusable upload password (at least ${limits.min_password} characters)`:(limits.require_download_password?'Separate download password':'Encryption password (required)'),'password','');password.minLength=limits.min_password;password.maxLength=256;password.autocomplete='new-password';password.required=true;
 if(kind==='inbox')bytes=field('Total inbox capacity (MiB)','number',limits.max_inbox_bytes/1048576,1,limits.max_inbox_bytes/1048576);
 function generatePassword(){const raw=crypto.getRandomValues(new Uint8Array(Math.ceil(Math.max(24,limits.min_password)*3/4)));password.value=btoa(String.fromCharCode(...raw)).replaceAll('+','-').replaceAll('/','_');}
 generatePassword();form.append(button('Generate another password',generatePassword),button('Copy password',async()=>{try{await navigator.clipboard.writeText(password.value);status.textContent='Encryption password copied.';}catch{status.textContent='Select and copy the password manually.';}}),button('Show password',event=>{const show=password.type==='password';password.type=show?'text':'password';event.currentTarget.textContent=show?'Hide password':'Show password';}));
 const submit=document.createElement('button');submit.type='submit';submit.textContent='Create transfer';form.append(submit);
 form.addEventListener('submit',async event=>{event.preventDefault();submit.disabled=true;try{
  const options={ttl:Math.floor(Number(hours.value)*3600)};
  if(password)options.password=password.value;
  if(kind==='inbox'){options.max_files=Number(uses.value);options.max_bytes=Math.floor(Number(bytes.value)*1048576);}else options.max_uses=Number(uses.value);
  await api('transfers',{kind,nodeId:node.fileid,options});status.textContent='Created. Keep this encryption password and send it separately. Your code will appear in NextShuttle when preparation finishes.';const saved=document.createElement('input');saved.type='password';saved.readOnly=true;saved.value=password.value;saved.setAttribute('aria-label','Saved encryption password');saved.autocomplete='off';const dashboard=document.createElement('a');dashboard.href=generateUrl('/apps/nextshuttle/');dashboard.textContent='Open my shares';status.append(saved,button('Copy encryption password',()=>navigator.clipboard.writeText(saved.value)),dashboard);form.remove();
 }catch(error){status.textContent=error.message;}finally{submit.disabled=false;}});
 dialog.append(title,name,form,status,button('Close',()=>{dialog.close();dialog.remove();}));document.body.append(dialog);dialog.showModal();
}

export function rotatePassword(save,minLength=16){
 const dialog=document.createElement('dialog');dialog.className='ns-dialog';
 const form=document.createElement('form'),label=document.createElement('label'),input=document.createElement('input'),status=document.createElement('p');
 label.textContent=`New upload password (at least ${minLength} characters)`;input.type='password';input.autocomplete='new-password';input.minLength=minLength;input.maxLength=256;input.required=true;label.append(input);status.role='status';
 const submit=document.createElement('button');submit.type='submit';submit.textContent='Change password';
 const hint=document.createElement('p');hint.textContent='Changing this password creates a new upload code. Share the updated code or link; uploads already received stay decryptable.';
 form.append(label,submit);dialog.append(hint,form,status,button('Cancel',()=>{dialog.close();dialog.remove();}));
 form.addEventListener('submit',async e=>{e.preventDefault();submit.disabled=true;try{await save(input.value);input.value='';dialog.close();dialog.remove();}catch(error){status.textContent=error.message;}finally{submit.disabled=false;}});
 document.body.append(dialog);dialog.showModal();input.focus();
}
