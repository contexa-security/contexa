// 일회용: 방문자 화면 몇 곳을 더 찍습니다(코드 변경 없음). 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR', reducedMotion: 'reduce' });
const page = await context.newPage();
for (const [path, name] of [['/summary/next', 'd-next'], ['/more', 'd-more'], ['/lab', 'd-lab'], ['/compare/rule', 'd-compare-rule'], ['/attack/request', 'd-attack-request'], ['/benchmark/limits', 'd-bench-limits']]) {
  await page.goto(`http://127.0.0.1:19180${path}?lng=ko`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(700);
  await page.screenshot({ path: `${out}/${name}.png` });
}
await context.close();
const mobile = await browser.newContext({ viewport: { width: 390, height: 844 }, locale: 'ko-KR', reducedMotion: 'reduce' });
const mpage = await mobile.newPage();
await mpage.goto('http://127.0.0.1:19180/?lng=ko', { waitUntil: 'networkidle' });
await mpage.waitForTimeout(700);
await mpage.screenshot({ path: `${out}/m-home-first.png` });
await browser.close();
console.log('ok');
