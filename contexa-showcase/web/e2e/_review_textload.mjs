// 일회용: 주 흐름 화면마다 첫 화면(뷰포트)에 보이는 글자 수와 누를 것의 수를 잽니다(코드 변경 없음). 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const route = JSON.parse(fs.readFileSync(new URL('../src/journey/route.json', import.meta.url), 'utf8'));
const extra = [['lab', '/lab'], ['bench', '/benchmark'], ['more', '/more'], ['adopt', '/adopt']];
const sizes = [['d', 1440, 900], ['m', 390, 844]];
const browser = await chromium.launch();
const rows = [];
for (const [tag, width, height] of sizes) {
  const context = await browser.newContext({ viewport: { width, height }, locale: 'ko-KR', reducedMotion: 'reduce' });
  const page = await context.newPage();
  // GUIDES=fake lists every guide video of the plan as recorded, so each screen carries its link (VP-5); the link's
  // words are a button's and are not counted.
  if (process.env.GUIDES === 'fake') {
    const recorded = JSON.parse(fs.readFileSync(new URL('../public/guides/guides.json', import.meta.url), 'utf8')).console;
    const list = JSON.parse(fs.readFileSync(new URL('../src/components/guide/guides.json', import.meta.url), 'utf8'));
    const body = JSON.stringify(Object.fromEntries(Object.entries(list).filter(([, entry]) => entry.kind !== 'legacy').map(([id]) => [id, { ...recorded, captionsNarrow: recorded.captions }])));
    await page.route('**/guides/guides.json', (request) => request.fulfill({ contentType: 'application/json', body }));
  }
  for (const [number, path, type] of [...route.map((s) => [s.number, s.path, s.type]), ...extra.map(([n, p]) => [n, p, '-'])]) {
    await page.goto(`${process.env.BASE ?? 'http://127.0.0.1:19180'}${path}?lng=ko`, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(500);
    const m = await page.evaluate(() => {
      const vh = window.innerHeight;
      const header = document.querySelector('header');
      const skipTop = header ? header.getBoundingClientRect().bottom : 0;
      let chars = 0;
      let words = 0;
      const closedAbove = (el) => { for (let d = el.closest('details:not([open])'); d; d = d.parentElement?.closest('details:not([open])') ?? null) { const s = el.closest('summary'); if (!(s && s.parentElement === d)) return true; } return false; };
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        const text = node.textContent.replace(/\s+/g, ' ').trim();
        if (!text) continue;
        const el = node.parentElement;
        if (!el || el.closest('script,style,noscript,[aria-hidden="true"], .visually-hidden')) continue;
        // 닫힌 접는 줄의 내용은 방문자에게 보이지 않는다(요약 줄만 보인다).
        if (closedAbove(el) || el.closest('[data-guide-slot]')) continue;
        const range = document.createRange();
        range.selectNodeContents(node);
        const r = range.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) continue;
        if (r.top >= vh || r.bottom <= skipTop) continue;
        const style = getComputedStyle(el);
        if (style.visibility === 'hidden' || style.display === 'none') continue;
        chars += text.replace(/\s/g, '').length;
        words += text.split(' ').length;
      }
      const all = document.body.innerText.replace(/\s/g, '').length;
      const actionable = [...document.querySelectorAll('main button, main a, main [role="button"], main input, main select, footer button, footer a')]
        .filter((e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.top < vh; }).length;
      return { chars, words, all, actionable, pageHeight: document.documentElement.scrollHeight };
    });
    rows.push({ tag, number, path, type, ...m });
  }
  await context.close();
}
await browser.close();
fs.writeFileSync(process.argv[2], JSON.stringify(rows, null, 1));
for (const r of rows.filter((x) => x.tag === 'd')) {
  console.log(`${r.number.padEnd(5)} ${r.type.padEnd(3)} ${r.path.padEnd(20)} 첫화면 ${String(r.chars).padStart(4)}자  전체 ${String(r.all).padStart(5)}자  누를것 ${String(r.actionable).padStart(2)}  높이 ${r.pageHeight}`);
}
