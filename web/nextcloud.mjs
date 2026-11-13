import {api,button} from './api.mjs';
async function refresh(){
 const target=document.getElementById('ns-transfers');if(!target)return;
 try{const {transfers}=await api('transfers');target.replaceChildren();
  if(!transfers.length){const p=document.createElement('p');p.textContent='Choose a file or folder in Files and select NextShuttle to create your first transfer.';target.append(p);}
  for(const t of transfers){const card=document.createElement('section');card.className='ns-card';const title=document.createElement('h3');title.textContent=t.label;
   const meta=document.createElement('p');meta.textContent=`${t.kind==='inbox'?'Upload inbox':'Download'} · ${t.state} · expires ${new Date(t.expires*1000).toLocaleString()}`;card.append(title,meta);
   if(t.code){const code=document.createElement('textarea');code.readOnly=true;code.value=t.url;code.setAttribute('aria-label','Transfer link');card.append(code,button('Copy link',()=>navigator.clipboard.writeText(t.url)),button('Copy code',()=>navigator.clipboard.writeText(t.code)));}
   if(['queued','preparing','ready','retry','revoking','exhausted'].includes(t.state))card.append(button(t.kind==='inbox'?'Revoke inbox and discard pending uploads':'Revoke',async()=>{try{await api(`transfers/${t.id}/revoke`,{});await refresh();}catch(e){alert(e.message);}}));
   if(t.state==='retry')card.append(button('Retry',async()=>{await api(`transfers/${t.id}/retry`,{});await refresh();}));
   if(t.kind==='inbox'&&t.state==='ready')card.append(button('Change upload password',async()=>{const password=prompt('New reusable upload password (at least 16 characters)');if(password)try{await api(`transfers/${t.id}/password`,{password});alert('Password changed.');}catch(e){alert(e.message);}}));
   target.append(card);
  }
 }catch(error){target.textContent=error.message;}
}
const settings=document.getElementById('ns-policy');
if(settings){settings.addEventListener('submit',async event=>{event.preventDefault();const fields=new FormData(settings),policy={};
 for(const [key,value]of fields){if(key==='groups'||key==='types')policy[key]=String(value).split(',').map(x=>x.trim()).filter(Boolean);else if(!['serviceToken','scannerToken','require_download_password'].includes(key))policy[key]=Number(value);}
 policy.require_download_password=settings.elements.require_download_password.checked;
 const status=document.getElementById('ns-settings-status');try{const result=await api('settings',{policy,serviceToken:fields.get('serviceToken'),scannerToken:fields.get('scannerToken')});status.textContent=result.message;settings.querySelectorAll('input[type=password]').forEach(x=>x.value='');}catch(error){status.textContent=error.message;}
});}
refresh();if(document.getElementById('ns-transfers'))setInterval(refresh,15000);
