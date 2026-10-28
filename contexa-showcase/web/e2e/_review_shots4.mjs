// 일회용: 접는 줄을 넣은 화면이 실제로 접혀 보이는지 확인합니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';
const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
for (const [tag, width, height] of [['d', 1440, 900], ['m', 390, 844]]) {
  const page = await (await browser.newContext({ viewport: { width, height }, locale: 'ko-KR', reducedMotion: 'reduce' })).newPage();
  for (const path of ['/intro/map', '/evidence/map', '/agent/burst']) {
    await page.goto(`http://127.0.0.1:5180${path}?lng=ko`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(700);
    await page.screenshot({ path: `${out}/${tag}${path.replace(/\W+/g, '-')}.png`, fullPage: true });
  }
}
await browser.close();
