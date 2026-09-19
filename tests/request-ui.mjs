// Explicit local UI fixture. Fails if Chromium, Vite or expected controls are absent.
// Run: npm run test:request-ui (start `npx vite --host 127.0.0.1` first).
import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
const root=process.env.CATMOS_UI_URL || 'http://127.0.0.1:1420';
if(!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(root))throw Error('UI evidence runner requires an explicit local server');
const output=new URL('./artifacts/request-ui/',import.meta.url);await mkdir(output,{recursive:true});
const browser=await chromium.launch({headless:true});const page=await browser.newPage({viewport:{width:1200,height:900},colorScheme:'dark'});const errors=[],network=[];
page.on('pageerror',e=>errors.push(String(e)));page.on('request',r=>network.push(r.url()));
try {
 await page.goto(`${root}/dev/request-preview`,{waitUntil:'networkidle'});
 await page.getByRole('heading',{name:'Maya',exact:true}).waitFor();
 assert.equal(await page.locator('article.intro').count(),1);assert.match(await page.locator('article.intro').innerText(),/autumn planting/);
 assert.equal(await page.getByRole('textbox').count(),0);assert.equal(await page.locator('article.intro a, article.intro img, article.intro iframe').count(),0);
 await page.screenshot({path:new URL('incoming-preview.png',output).pathname,fullPage:true});
 await page.getByRole('button',{name:'View group invitation',exact:true}).click();
 await page.getByRole('status').filter({hasText:'not accepted'}).waitFor();
 await page.getByRole('button',{name:'unavailable',exact:true}).click();
 await page.getByRole('heading',{name:'Content unavailable on this device'}).waitFor();assert.equal(await page.locator('article.intro').count(),0);
 await page.screenshot({path:new URL('unavailable-preview.png',output).pathname,fullPage:true});
 await page.getByRole('button',{name:'draft',exact:true}).click();await page.getByRole('textbox',{name:'Your message'}).fill('A local introduction');assert.equal(await page.getByRole('button',{name:'Send introduction',exact:true}).isDisabled(),true);
 await page.screenshot({path:new URL('browser-unsupported-draft.png',output).pathname,fullPage:true});
 await page.getByRole('button',{name:'accepted',exact:true}).click();assert.equal(await page.locator('[data-message-id]').count(),1);await page.screenshot({path:new URL('accepted-first-message.png',output).pathname,fullPage:true});
 await page.getByRole('button',{name:'note',exact:true}).click();await page.getByRole('button',{name:/View group invitation/}).waitFor();assert.match(await page.locator('.bubble-text').innerText(),/https:\/\/bsky.app/);assert.equal(await page.locator('iframe,.bluesky-embed').count(),0);await page.getByRole('button',{name:/View group invitation/}).click();await page.screenshot({path:new URL('accepted-invitation-note.png',output).pathname,fullPage:true});
 await page.getByRole('button',{name:'inbox',exact:true}).click();await page.getByRole('heading',{name:'Message requests',exact:true}).waitFor();await page.screenshot({path:new URL('requests-inbox.png',output).pathname,fullPage:true});
 assert.deepEqual(errors,[]);assert.equal(network.some(url=>url.includes('example.invalid')),false);
 await writeFile(new URL('evidence.json',output),JSON.stringify({kind:'local-ui-fixture-only',base:root,screenshots:6,errors,externalRequests:network.filter(url=>!url.startsWith(root)),assertions:['pending preview plain text only','no remote preview fetch','group navigation does not accept','unavailable preview truthful','browser producer unavailable','accepted first message single stable identity','accepted note literal reference navigation only']},null,2));
 console.log('PASS: 6 local UI screens; no end-to-end publication, native crypto or browser provider claim.');
} finally {await browser.close();}
