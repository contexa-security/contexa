// 일회용: 첫 화면(뷰포트)에 보이는 글을 글 덩어리별로 뽑아 줄일 곳을 찾습니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const route = JSON.parse(fs.readFileSync(new URL('../src/journey/route.json', import.meta.url), 'utf8'));
const only = process.argv[3] ? process.argv[3].split(',') : null;
const base = process.env.BASE ?? 'http://127.0.0.1:5180';
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR', reducedMotion: 'reduce' });
const page = await context.newPage();
const out = [];
for (const screen of route) {
  if (only && !only.includes(screen.number)) continue;
  await page.goto(`${base}${screen.path}?lng=ko`, { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(700);
  const rows = await page.evaluate(() => {
    const vh = window.innerHeight;
    const header = document.querySelector('header');
    const skipTop = header ? header.getBoundingClientRect().bottom : 0;
    const found = [];
    const closedAbove = (el) => { for (let d = el.closest('details:not([open])'); d; d = d.parentElement?.closest('details:not([open])') ?? null) { const s = el.closest('summary'); if (!(s && s.parentElement === d)) return true; } return false; };
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = node.textContent.replace(/\s+/g, ' ').trim();
      if (!text) continue;
      const el = node.parentElement;
      if (!el || el.closest('script,style,noscript,[aria-hidden="true"], .visually-hidden')) continue;
      // 닫힌 접는 줄의 내용은 방문자에게 보이지 않는다(요약 줄만 보인다).
      if (closedAbove(el)) continue;
      const range = document.createRange();
      range.selectNodeContents(node);
      const r = range.getBoundingClientRect();
      if (r.width === 0 || r.height === 0 || r.top >= vh || r.bottom <= skipTop) continue;
      const style = getComputedStyle(el);
      if (style.visibility === 'hidden' || style.display === 'none') continue;
      const zone = el.closest('[data-zone]')?.getAttribute('data-zone') ?? '-';
      found.push({ zone, size: Math.round(parseFloat(style.fontSize)), n: text.replace(/\s/g, '').length, text: text.slice(0, 70) });
    }
    return found;
  });
  const total = rows.reduce((sum, row) => sum + row.n, 0);
  out.push(`\n=== ${screen.number} ${screen.path} · ${total}자`);
  for (const row of rows) out.push(`  [${row.zone}] ${String(row.size).padStart(2)}px ${String(row.n).padStart(3)}자  ${row.text}`);
}
await browser.close();
fs.writeFileSync(process.argv[2], out.join('\n'));
console.log('ok');
