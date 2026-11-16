import {api,button,rotatePassword} from './api.mjs';
const stateLabels={queued:'Queued',preparing:'Preparing securely',ready:'Ready to share',retry:'Needs attention',rotating:'Updating password',revoking:'Revoking',revoked:'Revoked',expired:'Expired',exhausted:'Download limit reached',rejected:'Blocked by safety checks'};
let snapshot='',allTransfers=[],currentPolicy={};
function element(tag,text,className){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(className)node.className=className;return node;}
async function copy(value,control,status){try{await navigator.clipboard.writeText(value);const previous=control.textContent;control.textContent='Copied';status.textContent='Copied to clipboard.';setTimeout(()=>control.textContent=previous,1800);}catch{status.textContent='Clipboard unavailable. Select the value and copy it manually.';}}
function render(){
 const target=document.getElementById('ns-transfers');if(!target)return;
 const search=(document.getElementById('ns-search')?.value||'').toLowerCase(),filter=document.getElementById('ns-filter')?.value||'all';
 const rows=allTransfers.filter(t=>t.label.toLowerCase().includes(search)&&(filter==='all'||t.kind===filter));
 document.getElementById('ns-total').textContent=allTransfers.length;
 document.getElementById('ns-ready').textContent=allTransfers.filter(t=>t.state==='ready').length;
 document.getElementById('ns-inboxes').textContent=allTransfers.filter(t=>t.kind==='inbox'&&t.state==='ready').length;
 target.replaceChildren();
 if(!rows.length){target.append(element('div',allTransfers.length?'No transfers match your filters.':'Your first transfer starts in Files. Choose a file to share, or a folder to receive uploads.','ns-empty'));return;}
 for(const t of rows){
  const card=element('article',undefined,'ns-card'),heading=element('div',undefined,'ns-card-heading'),identity=element('div');
  identity.append(element('span',t.kind==='inbox'?'UPLOAD INBOX':'SHARED FILE','ns-eyebrow'),element('h2',t.label));
  const badge=element('span',stateLabels[t.state]||t.state,'ns-badge ns-state-'+t.state);heading.append(identity,badge);card.append(heading);
  const meta=element('div',undefined,'ns-meta');meta.append(element('span','Expires '+new Date(t.expires*1000).toLocaleString()));
  if(t.kind==='download'&&t.usage?.downloads!==undefined)meta.append(element('span',t.usage.downloads+' / '+(t.limits?.max_uses??'—')+' downloads'));
  if(t.kind==='inbox'&&t.usage?.files!==undefined)meta.append(element('span',t.usage.files+' / '+(t.limits?.max_files??'—')+' files received'));
  card.append(meta);const status=element('p','','ns-card-status');status.role='status';
  function secret(label,value,masked=false){
   const box=element('div',undefined,'ns-secret'),title=element('label',label),field=element(masked?'input':'textarea');if(!masked)field.rows=3;field.readOnly=true;field.value=value;if(masked)field.type='password';field.spellcheck=false;field.autocomplete='off';field.setAttribute('aria-label',label);title.append(field);box.append(title);
   const control=button('Copy '+label.toLowerCase(),()=>copy(value,control,status));box.append(control);
   if(masked)box.append(button('Show key',event=>{const show=field.type==='password';field.type=show?'text':'password';event.currentTarget.textContent=show?'Hide key':'Show key';}));
   return box;
  }
  if(t.code){
   card.append(secret('Share code',t.share_code||t.code));
   if(t.encryption_key)card.append(secret('Encryption key',t.encryption_key,true));
   const link=element('div',undefined,'ns-share-actions'),copyLink=button('Copy full link',()=>copy(t.url,copyLink,status)),open=element('a','Open public page','ns-link');open.href=t.url;open.target='_blank';open.rel='noopener noreferrer';copyLink.classList.add('primary');link.append(copyLink,open);card.append(link);
   card.append(element('p',t.protection==='password-encrypted'?'The full link includes the code and encryption key. Send the encryption password separately.':'Legacy share: its password controls access only. Create a new share for password-based encryption.','ns-hint'));
  }else if(['queued','preparing','retry'].includes(t.state))card.append(element('p','Your code appears here after private preparation and both malware scans finish. Nextcloud background jobs process this transfer.','ns-hint'));
  const controls=element('div',undefined,'ns-card-controls');
  if(['queued','preparing','ready','retry','revoking','rotating','exhausted'].includes(t.state))controls.append(button(t.kind==='inbox'?'Close inbox':'Revoke share',async()=>{if(t.kind==='inbox'&&!confirm('Close this inbox and discard uploads that have not been imported?'))return;try{await api(`transfers/${t.id}/revoke`,{});await refresh(true);}catch(e){status.textContent=e.message;}}));
  if(t.state==='retry')controls.append(button('Retry preparation',async()=>{try{await api(`transfers/${t.id}/retry`,{});await refresh(true);}catch(e){status.textContent=e.message;}}));
  if(t.kind==='inbox'&&t.state==='ready')controls.append(button('Change password',()=>rotatePassword(async password=>{await api(`transfers/${t.id}/password`,{password});await refresh(true);},currentPolicy.min_password)));
  card.append(controls,status);target.append(card);
 }
}
async function refresh(force=false){
 if(!document.getElementById('ns-transfers'))return;
 try{const data=await api('transfers'),next=JSON.stringify(data);if(force||next!==snapshot){snapshot=next;allTransfers=data.transfers;currentPolicy=data.policy;render();}document.getElementById('ns-refresh-status').textContent='Up to date';}
 catch(error){document.getElementById('ns-refresh-status').textContent=error.message;}
}
for(const id of ['ns-search','ns-filter'])document.getElementById(id)?.addEventListener('input',render);
document.getElementById('ns-refresh')?.addEventListener('click',()=>refresh(true));
const settings=document.getElementById('ns-policy');
if(settings){settings.addEventListener('submit',async event=>{event.preventDefault();const fields=new FormData(settings),policy={};
 for(const [key,value]of fields){if(key==='groups'||key==='types')policy[key]=String(value).split(',').map(x=>x.trim()).filter(Boolean);else if(!['serviceToken','scannerToken','require_download_password'].includes(key))policy[key]=Number(value);}
 policy.require_download_password=settings.elements.require_download_password.checked;
 const status=document.getElementById('ns-settings-status');try{const result=await api('settings',{policy,serviceToken:fields.get('serviceToken'),scannerToken:fields.get('scannerToken')});status.textContent=result.message;settings.querySelectorAll('input[type=password]').forEach(x=>x.value='');}catch(error){status.textContent=error.message;}
});}
refresh();if(document.getElementById('ns-transfers'))setInterval(refresh,15000);
