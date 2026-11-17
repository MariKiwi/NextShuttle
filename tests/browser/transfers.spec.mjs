import {test,expect} from '@playwright/test';
import {protect} from '../../web/protection.mjs';
import {readFile} from 'node:fs/promises';
import {encrypt,decrypt,ready,b64} from '../../web/crypto.mjs';
const sodium=await ready(),privateURL='https://localhost:9085/api/v1/';
test.beforeEach(async({request})=>{expect((await request.post('https://localhost:9085/__fixture/reset-rate-budget',{headers:{Authorization:'Bearer '+'r'.repeat(64)},data:{}})).ok()).toBeTruthy();});
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
 const context=await browser.newContext({ignoreHTTPSErrors:true}),page=await context.newPage();
 await page.goto('https://localhost:9085/');await page.getByLabel('Administrator password').fill('a'.repeat(64));await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.locator('#summary')).toContainText('Storage capacity');await expect(page.getByRole('heading',{name:'Transfer overview',exact:true})).toBeVisible();
 const row=page.locator('#transfers p').filter({hasText:t.id});await row.getByRole('button',{name:'Revoke',exact:true}).click();
 await expect(page.locator('#transfers').getByText(t.id,{exact:false})).toHaveCount(0);
 const waiting=page.waitForEvent('download');await page.getByRole('button',{name:'Export complete audit journal'}).click();const download=await waiting;
 const text=(await readFile(await download.path())).toString();expect(text).toContain('admin_page_accessed');expect(text).not.toContain(t.access_token);expect(text).not.toContain('r'.repeat(64));
 await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.getByLabel('Administrator password')).toBeVisible();
 await context.close();
});

test('v2 public downloads accept separate code/key and keep the password local',async({page,request})=>{
 const password='a separate local encryption password',id=sodium.to_hex(sodium.randombytes_buf(16)),token=b64(sodium.randombytes_buf(32)),seed=sodium.randombytes_buf(32),salt=b64(sodium.randombytes_buf(16));
 const code=`D2.${id}.${token}.${b64(seed)}.${salt}`,protection=await protect(code,password),encrypted=await encrypt(new File(['password protected browser content'],'protected.txt'),null,protection);
 await privatePost(request,'downloads',{id,access_token:token,bytes:encrypted.blob.size,ttl:3600,password:protection.authorization});
 expect((await request.put(privateURL+`downloads/${id}/blob`,{headers:{Authorization:'Bearer '+'r'.repeat(64)},data:Buffer.from(await encrypted.blob.arrayBuffer())})).ok()).toBeTruthy();
 const sent=[];page.on('request',r=>{if(r.url().includes('/api/'))sent.push(r.postData()||'');});
 await page.goto('/nextshuttle/');await page.getByLabel('Transfer code').fill(`D2.${id}.${token}.${salt}`);
 await page.getByLabel('Encryption key',{exact:false}).fill(b64(seed));await page.getByLabel('Password',{exact:false}).fill('an incorrect long password');
 await page.getByRole('button',{name:'Decrypt and download'}).click();await expect(page.getByRole('status')).toContainText('Code invalid');
 await page.getByLabel('Password',{exact:false}).fill(password);const waiting=page.waitForEvent('download');await page.getByRole('button',{name:'Decrypt and download'}).click();
 const download=await waiting;expect((await readFile(await download.path())).toString()).toBe('password protected browser content');
 expect(sent.join(' ')).not.toContain(password);expect(sent.join(' ')).not.toContain(b64(seed));
});
test('v2 public uploads are encrypted with password and inbox key',async({page,request})=>{
 const box=sodium.crypto_box_keypair(),id=sodium.to_hex(sodium.randombytes_buf(16)),salt=b64(sodium.randombytes_buf(16)),password='a password protected browser inbox',code=`U2.${id}.${b64(box.publicKey)}.${salt}`,protection=await protect(code,password);
 await privatePost(request,'inboxes',{id,password:protection.authorization,ttl:3600,max_files:3,max_bytes:1048576,public_key:sodium.to_base64(box.publicKey,sodium.base64_variants.ORIGINAL)});
 const sent=[];page.on('request',r=>{if(r.url().includes('/api/')&&r.method()==='POST')sent.push(r.postData()||'');});
 await page.goto('/nextshuttle/#'+code);await page.getByLabel('Password',{exact:false}).fill(password);await page.getByLabel('File',{exact:true}).setInputFiles({name:'protected.txt',mimeType:'text/plain',buffer:Buffer.from('private password protected upload')});
 await page.getByRole('button',{name:'Encrypt and upload'}).click();await expect(page.getByRole('status')).toContainText('Encrypted upload received');
 expect(sent.join(' ')).not.toContain(password);
 const response=await request.get(privateURL+'uploads',{headers:{Authorization:'Bearer '+'r'.repeat(64)}}),upload=(await response.json()).find(r=>r.inbox===id);
 const fetched=await request.get(privateURL+`uploads/${upload.id}/blob`,{headers:{Authorization:'Bearer '+'r'.repeat(64)}}),data=new Uint8Array(await fetched.body());
 expect(await (await decrypt(data,null,box,protection)).blob.text()).toBe('private password protected upload');
});


test('redesigned portal and operations dashboard fit the viewport',async({page},testInfo)=>{
 await page.goto('/nextshuttle/');
 await expect(page.getByRole('heading',{name:'Unlock your transfer'})).toBeVisible();
 await expect(page.locator('footer')).toContainText('0.3.1');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.screenshot({path:testInfo.outputPath('public.png'),fullPage:true});
 await page.goto('https://localhost:9085/');
 await page.getByLabel('Administrator password').fill('a'.repeat(64));
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.locator('#metric-downloads')).not.toHaveText('—');
 await expect(page.getByRole('heading',{name:'Transfer overview'})).toBeVisible();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.screenshot({path:testInfo.outputPath('admin.png'),fullPage:true});
});
