// 일회용: 글자 규격을 바꾼 뒤 주 흐름 화면마다 가로 넘침과 잘린 글(말줄임), 겹침 의심 요소를 두 폭에서 찾습니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const route = JSON.parse(fs.readFileSync(new URL('../src/journey/route.json', import.meta.url), 'utf8'));
const sizes = [['d', 1440, 900], ['m', 390, 844]];
const browser = await chromium.launch();
let problems = 0;
for (const [tag, width, height] of sizes) {
  const context = await browser.newContext({ viewport: { width, height }, locale: 'ko-KR', reducedMotion: 'reduce' });
  const page = await context.newPage();
  for (const screen of route) {
    await page.goto(`${process.env.BASE ?? 'http://127.0.0.1:5180'}${screen.path}?lng=ko`, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(400);
    const m = await page.evaluate(() => {
      const w = window.innerWidth;
      const over = document.documentElement.scrollWidth - w;
      const offenders = [];
      const clipped = [];
      for (const el of document.querySelectorAll('main *')) {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) continue;
        const style = getComputedStyle(el);
        if (style.position === 'fixed') continue;
        if (r.right > w + 1 && offenders.length < 3) {
          offenders.push(`${el.tagName.toLowerCase()}.${String(el.className).split(' ')[0]} 오른쪽 ${Math.round(r.right)}`);
        }
        if (el.scrollWidth > el.clientWidth + 2 && ['hidden', 'clip'].includes(style.overflowX) && el.children.length === 0 && clipped.length < 3) {
          clipped.push(`${el.tagName.toLowerCase()}.${String(el.className).split(' ')[0]} 잘림 ${el.scrollWidth - el.clientWidth}`);
        }
      }
      const h1 = document.querySelector('main h1');
      const title = h1 ? Math.round(h1.getBoundingClientRect().height) : 0;
      return { over, offenders, clipped, title, height: document.documentElement.scrollHeight };
    });
    const bad = m.over > 1 || m.offenders.length > 0 || m.clipped.length > 0;
    if (bad) {
      problems += 1;
    }
    console.log(`${tag} ${screen.number.padEnd(4)} ${screen.path.padEnd(22)} 제목높이 ${String(m.title).padStart(3)} 전체높이 ${String(m.height).padStart(5)} ${bad ? `넘침 ${m.over} ${m.offenders.join(' | ')} ${m.clipped.join(' | ')}` : ''}`);
  }
  await context.close();
}
await browser.close();
console.log(`문제 화면 ${problems}`);
