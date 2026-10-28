// 일회용: 주 흐름 33화면의 본문 글을 모두 뽑아 파일로 저장합니다(코드 변경 없음). 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const route = JSON.parse(fs.readFileSync(new URL('../src/journey/route.json', import.meta.url), 'utf8'));
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR', reducedMotion: 'reduce' });
const page = await context.newPage();
const out = {};
for (const s of route) {
  await page.goto(`http://127.0.0.1:19180${s.path}?lng=ko`, { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(600);
  out[s.number] = await page.evaluate(() => {
    const root = document.querySelector('main') ?? document.body;
    return root.innerText.replace(/\n{2,}/g, '\n').trim();
  });
}
await browser.close();
fs.writeFileSync(process.argv[2], JSON.stringify(out, null, 1));
console.log('ok', Object.keys(out).length);
