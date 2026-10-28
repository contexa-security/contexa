// 일회용: 모바일에서 잘린 span이 무엇인지 확인합니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 390, height: 844 }, locale: 'ko-KR', reducedMotion: 'reduce' })).newPage();
for (const path of ['/choose', '/attack/request', '/deeper']) {
  await page.goto(`http://127.0.0.1:5180${path}?lng=ko`, { waitUntil: 'networkidle' });
  const rows = await page.evaluate(() => [...document.querySelectorAll('main *, header *')].filter((el) => { const s = getComputedStyle(el); return el.scrollWidth > el.clientWidth + 2 && ['hidden', 'clip'].includes(s.overflowX) && el.children.length === 0 && !String(el.className).includes('visually-hidden'); }).map((el) => `${el.tagName} "${el.textContent.slice(0, 40)}" parent=${el.parentElement.tagName}.${String(el.parentElement.className).split(' ')[0]} sw=${el.scrollWidth} cw=${el.clientWidth} ov=${getComputedStyle(el).textOverflow}`));
  console.log(path, JSON.stringify(rows, null, 1));
}
await browser.close();
