// 일회용: 휴대폰에서 3-1·6-6의 높이를 확인합니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 390, height: 844 }, locale: 'ko-KR', reducedMotion: 'reduce' })).newPage();
for (const path of ['/evidence/map', '/agent/burst']) {
  await page.goto(`http://127.0.0.1:5180${path}?lng=ko`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);
  console.log(path, await page.evaluate(() => document.documentElement.scrollHeight));
}
await browser.close();
