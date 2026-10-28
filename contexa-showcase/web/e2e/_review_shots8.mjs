// 일회용: 휴대폰과 데스크톱에서 5-3의 높이와 모습을 확인합니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
const browser = await chromium.launch();
for (const [tag, w, h] of [['m', 390, 844], ['d', 1440, 900]]) {
  const page = await (await browser.newContext({ viewport: { width: w, height: h }, locale: 'ko-KR', reducedMotion: 'reduce' })).newPage();
  await page.goto('http://127.0.0.1:5180/insider/reason?lng=ko', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1200);
  console.log(tag, await page.evaluate(() => document.documentElement.scrollHeight), await page.evaluate(() => document.querySelector('details[data-fold="hypotheses"]')?.open));
}
await browser.close();
