// 일회용: 에이전트 갈래를 실제로 한 번 실행해 각 화면의 글 양을 잽니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const base = process.env.BASE ?? 'http://127.0.0.1:5180';
const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR', reducedMotion: 'reduce' });
const page = await context.newPage();

async function stats(name) {
  await page.waitForTimeout(900);
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
  console.log(name.padEnd(24), page.url().replace(base, '').padEnd(34), `첫화면 ${String(m.chars).padStart(4)}자 전체 ${String(m.all).padStart(5)}자 높이 ${m.height}`);
}

await page.goto(`${base}/agent?lng=ko`, { waitUntil: 'networkidle' });
await stats('A1-pick');
await page.click('[data-choice="N1"]');
await page.waitForURL(/agent\/request/);
await stats('6-1-request');
await page.locator('label:has(input[name="call"])').first().click();
await page.locator('button[data-main]').click();
await page.waitForURL(/agent\/console/, { timeout: 30000 });
await stats('6-2-console-start');
await page.waitForSelector('a[data-main]:not([aria-disabled="true"])', { timeout: 240000 }).catch(() => {});
await stats('6-2-console-end');
for (const path of ['/agent/result', '/agent/reason', '/agent/confirm', '/agent/end', '/agent/burst', '/agent/next']) {
  await page.goto(`${base}${path}?lng=ko`, { waitUntil: 'networkidle' });
  await stats(path.slice(1).replace('/', '-'));
}
await browser.close();
