// Disposable: which POSTs the agent menu screens send (the user may delete it).
import { chromium } from '@playwright/test';
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const posts = [];
page.on('request', (r) => { if (r.method() !== 'GET') posts.push(`${r.method()} ${r.url().replace('http://127.0.0.1:19180', '')} ${r.postData() ?? ''}`.slice(0, 200)); });
await page.goto('http://127.0.0.1:19180/lab/agent?lng=ko', { waitUntil: 'networkidle' });
await page.getByRole('radiogroup', { name: '사례' }).waitFor();
await page.getByRole('button', { name: '예상 없이 바로 보기' }).click();
await page.goto('http://127.0.0.1:19180/agent/burst?lng=ko', { waitUntil: 'networkidle' });
await page.goto('http://127.0.0.1:19180/benchmark/agent?lng=ko', { waitUntil: 'networkidle' });
console.log(posts.join('\n') || 'no POST');
await browser.close();
