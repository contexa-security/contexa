// 일회용: 휴대폰에서 3-1·6-6·7-2의 전체 모습과 문서 높이를 찍습니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';
const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 390, height: 844 }, locale: 'ko-KR', reducedMotion: 'reduce' })).newPage();
for (const path of ['/evidence/map', '/agent/burst', '/compare/change']) {
  await page.goto(`http://127.0.0.1:5180${path}?lng=ko`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);
  const h = await page.evaluate(() => ({ doc: document.documentElement.scrollHeight, body: document.body.scrollHeight, main: document.querySelector('main')?.scrollHeight }));
  console.log(path, JSON.stringify(h));
  await page.screenshot({ path: `${out}/m${path.replace(/\W+/g, '-')}.png`, fullPage: true });
}
await browser.close();
