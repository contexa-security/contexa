// 일회용: 지정한 폭에서 화면 가로로 넘치는 요소를 찾습니다(부모보다 먼저 가장 안쪽 요소). 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';

const base = process.env.BASE ?? 'http://127.0.0.1:5180';
const width = Number(process.env.W ?? 641);
const lng = process.env.LNG ?? 'en';
const paths = (process.env.P ?? 'person,agent/result').split(',');
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width, height: 720 }, locale: lng === 'en' ? 'en-US' : 'ko-KR', reducedMotion: 'reduce' });
const page = await context.newPage();
for (const path of paths) {
  await page.goto(`${base}/${path}?lng=${lng}`, { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(500);
  const m = await page.evaluate(() => {
    const out = [];
    const closed = (el) => {
      for (let d = el.closest('details:not([open])'); d; d = d.parentElement?.closest('details:not([open])') ?? null) {
        const s = el.closest('summary');
        if (!(s && s.parentElement === d)) return true;
      }
      return false;
    };
    for (const el of document.querySelectorAll('body *')) {
      if (closed(el)) continue;
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.right <= window.innerWidth + 1) continue;
      out.push({ tag: el.tagName, cls: String(el.className).slice(0, 50), right: Math.round(r.right), width: Math.round(r.width), text: (el.textContent ?? '').trim().slice(0, 40), depth: [...(function* () { for (let p = el; p; p = p.parentElement) yield p; })()].length });
    }
    out.sort((a, b) => b.depth - a.depth);
    return { scroll: document.documentElement.scrollWidth, inner: window.innerWidth, deepest: out.slice(0, 6) };
  });
  console.log(path, width, JSON.stringify(m, null, 1));
}
await browser.close();
