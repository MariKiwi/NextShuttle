import {test,expect} from '@playwright/test';
import {readFile} from 'node:fs/promises';
import {encrypt,decrypt,ready,b64} from '../../web/crypto.mjs';
const sodium=await ready(),privateURL='http://127.0.0.1:9085/api/v1/';
async function privatePost(request,path,data){const r=await request.post(privateURL+path,{headers:{Authorization:'Bearer '+'r'.repeat(64)},data});expect(r.ok()).toBeTruthy();return r.json();}
test('protected download decrypts in a real browser under CSP',async({page,request})=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const input=new File(['ordinary browser download'],'browser.txt'),encrypted=await encrypt(input);
 const t=await privatePost(request,'downloads',{bytes:encrypted.blob.size,ttl:3600,password:'a separate browser password'});
 const put=await request.put(privateURL+`downloads/${t.id}/blob`,{headers:{Authorization:'Bearer '+'r'.repeat(64)},data:Buffer.from(await encrypted.blob.arrayBuffer())});expect(put.ok()).toBeTruthy();
 const code=`D.${t.id}.${t.access_token}.${b64(encrypted.key)}`;
 await page.goto('/nextshuttle/#'+code);await expect(page).toHaveURL(/nextshuttle\/$/);
 await page.getByLabel('Password',{exact:false}).fill('not the correct password');await page.getByRole('button',{name:'Decrypt and download'}).click();
 await expect(page.getByRole('status')).toContainText('Code invalid');
 await page.getByLabel('Password',{exact:false}).fill('a separate browser password');
 const waiting=page.waitForEvent('download');await page.getByRole('button',{name:'Decrypt and download'}).click();
 const download=await waiting;expect(download.suggestedFilename()).toBe('browser.txt');expect((await readFile(await download.path())).toString()).toBe('ordinary browser download');
 expect(errors).toEqual([]);
});
test('upload stays encrypted on the relay and binds the trusted inbox key',async({page,request})=>{
 const box=sodium.crypto_box_keypair(),password='a static browser upload password';
 const inbox=await privatePost(request,'inboxes',{password,ttl:3600,max_files:4,max_bytes:1048576,public_key:sodium.to_base64(box.publicKey,sodium.base64_variants.ORIGINAL)});
 await page.goto(`/nextshuttle/#U.${inbox.id}.${b64(box.publicKey)}`);
 await page.getByLabel('Password',{exact:false}).fill(password);
 await page.getByLabel('File',{exact:true}).setInputFiles({name:'incoming.txt',mimeType:'text/plain',buffer:Buffer.from('ordinary browser upload')});
 await page.getByRole('button',{name:'Encrypt and upload'}).click();await expect(page.getByRole('status')).toContainText('Encrypted upload received');
 const list=await request.get(privateURL+'uploads',{headers:{Authorization:'Bearer '+'r'.repeat(64)}});const rows=await list.json();const upload=rows.find(r=>r.inbox===inbox.id);expect(upload).toBeTruthy();
 const fetched=await request.get(privateURL+`uploads/${upload.id}/blob`,{headers:{Authorization:'Bearer '+'r'.repeat(64)}});const bytes=new Uint8Array(await fetched.body());
 expect(Buffer.from(bytes).includes(Buffer.from('ordinary browser upload'))).toBeFalsy();
 const plain=await decrypt(bytes,null,box);expect(await plain.blob.text()).toBe('ordinary browser upload');
 const wrong=sodium.crypto_box_keypair();await page.goto(`/nextshuttle/#U.${inbox.id}.${b64(wrong.publicKey)}`);
 await page.getByLabel('Password',{exact:false}).fill(password);await page.getByLabel('File',{exact:true}).setInputFiles({name:'incoming.txt',mimeType:'text/plain',buffer:Buffer.from('must not send')});
 await page.getByRole('button',{name:'Encrypt and upload'}).click();await expect(page.getByRole('status')).toContainText('does not match');
});
test('private admin authentication, CSRF and audit export work in-browser',async({browser,request})=>{
 const t=await privatePost(request,'downloads',{bytes:4,ttl:3600});
 const context=await browser.newContext({httpCredentials:{username:'admin',password:'a'.repeat(64)}}),page=await context.newPage();
 await page.goto('http://127.0.0.1:9085/');await expect(page.getByRole('heading',{name:'NextShuttle',exact:true})).toBeVisible();
 const row=page.locator('#transfers p').filter({hasText:t.id});await row.getByRole('button',{name:'Revoke',exact:true}).click();
 await expect(page.locator('#transfers').getByText(t.id,{exact:false})).toHaveCount(0);
 const waiting=page.waitForEvent('download');await page.getByRole('button',{name:'Export complete audit journal'}).click();const download=await waiting;
 const text=(await readFile(await download.path())).toString();expect(text).toContain('admin_page_accessed');expect(text).not.toContain(t.access_token);expect(text).not.toContain('r'.repeat(64));
 await context.close();
});
