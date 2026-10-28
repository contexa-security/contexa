// 일회용: 개발 서버(실제 포털 API)에서 방문자 한 명이 사람 갈래(공격)와 내부자, 에이전트를 실제로 실행해 보며 결과·이유 화면의 글 양을 잽니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const base = process.env.BASE ?? 'http://127.0.0.1:5180';
const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR', reducedMotion: 'reduce' });
const page = await context.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(String(e).slice(0, 200)));

async function stats(name) {
  await page.waitForTimeout(800);
  const m = await page.evaluate(() => {
    const vh = window.innerHeight;
    let chars = 0;
    let all = 0;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = n.textContent.replace(/\s+/g, '');
      if (!text) continue;
      const el = n.parentElement;
      if (!el || el.closest('script,style,noscript,header[data-zone="top"]')) continue;
      const r = document.createRange();
      r.selectNodeContents(n);
      const b = r.getBoundingClientRect();
      if (b.width === 0) continue;
      all += text.length;
      if (b.top < vh && b.bottom > 0) chars += text.length;
    }
    return { chars, all, height: document.documentElement.scrollHeight };
  });
  await page.screenshot({ path: `${out}/${name}.png` });
  console.log(name.padEnd(22), page.url().replace(base, '').padEnd(32), `첫화면 ${String(m.chars).padStart(4)}자 전체 ${String(m.all).padStart(5)}자 높이 ${m.height}`);
}

async function runCase(startPath, predictLabel, name, consoleWaitMs = 90000) {
  await page.goto(`${base}${startPath}?lng=ko`, { waitUntil: 'networkidle' });
  await stats(`${name}-request`);
  await page.locator('label', { hasText: predictLabel }).first().click();
  await page.locator('button[data-main]').click();
  await page.waitForURL(/console/, { timeout: 30000 }).catch(() => {});
  await page.waitForTimeout(2000);
  await stats(`${name}-console-start`);
  // the console ends when its main link names the result; wait for an enabled link out of the console
  await page.waitForSelector('a[data-main]:not([aria-disabled="true"])', { timeout: consoleWaitMs }).catch(() => {});
  await stats(`${name}-console-end`);
}

await page.goto(`${base}/?lng=ko`, { waitUntil: 'networkidle' });
await runCase('/attack/request', '차단', '2-attack');
await page.goto(`${base}/attack/result?lng=ko`, { waitUntil: 'networkidle' });
await stats('2-3-result');
await page.goto(`${base}/normal/request?lng=ko`, { waitUntil: 'networkidle' });
await runCase('/normal/request', '허용', '4-normal');
await page.goto(`${base}/normal/diff?lng=ko`, { waitUntil: 'networkidle' });
await stats('4-3-diff');
await runCase('/insider/request', '차단', '5-insider');
await page.goto(`${base}/insider/reason?lng=ko`, { waitUntil: 'networkidle' });
await stats('5-3-insider-reason');
for (const path of ['/evidence/map', '/evidence/prompt', '/evidence/verdict', '/compare/rule', '/compare/change', '/compare/runs', '/summary']) {
  await page.goto(`${base}${path}?lng=ko`, { waitUntil: 'networkidle' });
  await stats(path.slice(1).replace('/', '-'));
}
if (errors.length) console.log('errors', errors.slice(0, 3));
await context.storageState({ path: `${out}/visitor-state.json` });
await browser.close();
