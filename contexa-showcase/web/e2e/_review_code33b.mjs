// 일회용: 3-3을 반복해 불러 "마지막 줄에 글자 하나" 텍스트가 나오는 상태를 잡고 그 요소를 보여 줍니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';

const base = process.env.BASE ?? 'http://127.0.0.1:19180';
const tries = Number(process.env.N ?? 12);
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: Number(process.env.W ?? 1440), height: 900 }, locale: 'ko-KR', reducedMotion: 'reduce' });
const page = await context.newPage();
const seen = new Set();
for (let i = 0; i < tries; i += 1) {
  await page.goto(`${base}/evidence/verdict?lng=ko`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(600);
  const found = await page.evaluate(() => {
    const out = [];
    const closedAbove = (el) => {
      for (let d = el.closest('details:not([open])'); d; d = d.parentElement?.closest('details:not([open])') ?? null) {
        const s = el.closest('summary');
        if (!(s && s.parentElement === d)) return true;
      }
      return false;
    };
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const range = document.createRange();
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = node.textContent ?? '';
      if (text.trim().length < 2 || node.parentElement?.closest('[aria-hidden="true"]')) continue;
      if (closedAbove(node.parentElement)) continue;
      const tops = (from, to) => {
        range.setStart(node, from);
        range.setEnd(node, to);
        return [...range.getClientRects()].filter((rect) => rect.width > 0).map((rect) => Math.round(rect.top));
      };
      const lines = new Set(tops(0, text.length));
      if (lines.size < 2) continue;
      const last = Math.max(...lines);
      let letters = 0;
      let tail = '';
      for (let k = text.length - 1; k >= 0; k -= 1) {
        if (/\s/.test(text[k] ?? '')) continue;
        if (Math.max(...tops(k, k + 1)) !== last) break;
        tail = text[k] + tail;
        if (/[\p{L}\p{N}]/u.test(text[k] ?? '')) letters += 1;
      }
      if (letters === 1) {
        const el = node.parentElement;
        const box = el.getBoundingClientRect();
        out.push({
          text: text.trim().slice(0, 60),
          tail,
          tag: el.tagName,
          cls: String(el.className).slice(0, 40),
          parent: `${el.parentElement?.tagName}.${String(el.parentElement?.className).slice(0, 40)}`,
          width: Math.round(box.width),
          ow: getComputedStyle(el).overflowWrap,
          wb: getComputedStyle(el).wordBreak,
          font: getComputedStyle(el).fontFamily.slice(0, 20),
        });
      }
    }
    return out;
  });
  const key = JSON.stringify(found);
  if (!seen.has(key)) {
    seen.add(key);
    console.log(`#${i + 1}`, key);
  }
}
console.log('서로 다른 상태', seen.size);
await browser.close();
