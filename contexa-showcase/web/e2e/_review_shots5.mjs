// 일회용: 휴대폰에서 긴 화면 세 곳의 전체 모습을 찍습니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';
const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 390, height: 844 }, locale: 'ko-KR', reducedMotion: 'reduce' })).newPage();
for (const path of ['/insider/reason', '/agent/confirm', '/compare/change']) {
  await page.goto(`http://127.0.0.1:5180${path}?lng=ko`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${out}/m${path.replace(/\W+/g, '-')}.png`, fullPage: true });
}
await browser.close();
