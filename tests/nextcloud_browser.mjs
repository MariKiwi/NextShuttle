import {chromium,expect} from '@playwright/test';
import {mkdir} from 'node:fs/promises';
const base='https://localhost:9083',browser=await chromium.launch();
await mkdir('test-results',{recursive:true});
try{
 const context=await browser.newContext({ignoreHTTPSErrors:true,permissions:['clipboard-read','clipboard-write']}),page=await context.newPage();
 await page.goto(base+'/login');
 const token=await page.locator('[data-requesttoken]').first().getAttribute('data-requesttoken');
 const login=await context.request.post(base+'/login',{form:{user:'alice',password:'ephemeral-ci-password-246810',requesttoken:token,redirect_url:'/index.php/apps/nextshuttle/'},headers:{Origin:base,Referer:base+'/login'},maxRedirects:0});
 expect([302,303]).toContain(login.status());
 await page.goto(base+'/index.php/apps/nextshuttle/');
 await expect(page.locator('.ns-header h1')).toHaveText('NextShuttle');
 const card=page.locator('.ns-card').filter({has:page.getByLabel('Share code',{exact:true})}).first();
 await expect(card.getByLabel('Share code',{exact:true})).toBeVisible();
 const share=await card.getByLabel('Share code',{exact:true}).inputValue(),key=await card.getByLabel('Encryption key',{exact:true}).inputValue();
 expect(share.startsWith('D2.')).toBeTruthy();expect(share).not.toContain(key);
 await card.getByRole('button',{name:'Copy share code',exact:true}).click();expect(await page.evaluate(()=>navigator.clipboard.readText())).toBe(share);
 await card.getByRole('button',{name:'Show key',exact:true}).click();await expect(card.getByLabel('Encryption key',{exact:true})).toHaveAttribute('type','text');
 await page.getByLabel('Find a transfer').fill('there-is-no-such-transfer');await expect(page.getByText('No transfers match your filters.')).toBeVisible();
 await page.getByLabel('Find a transfer').fill('');
 await page.setViewportSize({width:1440,height:1000});await page.screenshot({path:'test-results/nextcloud-dashboard-desktop.png',fullPage:true});
 await page.setViewportSize({width:390,height:844});await page.screenshot({path:'test-results/nextcloud-dashboard-mobile.png',fullPage:true});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
 console.log('Real Nextcloud dashboard: visible code/key, clipboard, search and responsive layout passed');
 await context.close();
}finally{await browser.close();}
