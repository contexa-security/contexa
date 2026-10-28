// 일회용: 폭 1280(e2e와 같은 폭)에서 영어 머리글이 넘치는 화면을 찾습니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const base = process.env.BASE ?? 'http://127.0.0.1:19180';
const route = JSON.parse(fs.readFileSync(new URL('../src/journey/route.json', import.meta.url), 'utf8'));
const widths = (process.env.W ?? '1280').split(',').map(Number);
const browser = await chromium.launch();
for (const width of widths) {
  const context = await browser.newContext({ viewport: { width, height: 720 }, locale: process.env.LNG === 'ko' ? 'ko-KR' : 'en-US', reducedMotion: 'reduce' });
  const page = await context.newPage();
  for (const screen of route) {
    await page.goto(`${base}${screen.path}?lng=${process.env.LNG ?? 'en'}`, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(400);
    const m = await page.evaluate(() => {
      const header = document.querySelector('header');
      const kids = header ? [...header.querySelectorAll('*')].filter((e) => e.getBoundingClientRect().right > window.innerWidth + 1) : [];
      return {
        scrollWidth: document.documentElement.scrollWidth,
        inner: window.innerWidth,
        headerWidth: header ? Math.round(header.getBoundingClientRect().width) : 0,
        over: kids.slice(0, 3).map((e) => `${e.tagName}.${String(e.className).slice(0, 30)}:${Math.round(e.getBoundingClientRect().right)}`),
        counter: (header?.querySelector('[data-zone="counter"], .counter')?.textContent ?? '').slice(0, 60),
      };
    });
    const bad = m.scrollWidth > m.inner + 1;
    console.log(`${width} ${screen.number.padEnd(4)} ${bad ? 'OVER' : 'ok  '} scroll ${m.scrollWidth} ${bad ? JSON.stringify(m.over) : ''}`);
  }
  await context.close();
}
await browser.close();
