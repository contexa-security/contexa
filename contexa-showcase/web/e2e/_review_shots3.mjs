// 일회용: 글자 규격을 바꾼 뒤 대표 화면을 두 폭에서 찍습니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';
const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
for (const [tag, width, height, paths] of [
  ['d', 1440, 900, ['/', '/choose', '/attack/request', '/evidence/prompt', '/insider/reason', '/summary']],
  ['m', 390, 844, ['/', '/attack/request', '/insider/reason']],
]) {
  const page = await (await browser.newContext({ viewport: { width, height }, locale: 'ko-KR', reducedMotion: 'reduce' })).newPage();
  for (const path of paths) {
    await page.goto(`http://127.0.0.1:5180${path}?lng=ko`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(600);
    await page.screenshot({ path: `${out}/${tag}${path.replace(/\W+/g, '-')}.png` });
  }
}
await browser.close();
