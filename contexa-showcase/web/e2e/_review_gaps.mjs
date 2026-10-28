// 일회용: 한 화면의 본문 블록들의 위치와 간격을 봅니다(링크 포함 상태). 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const path = process.argv[2];
const width = Number(process.argv[3] ?? 390);
const base = process.env.BASE ?? 'http://127.0.0.1:5180';
const recorded = JSON.parse(fs.readFileSync(new URL('../public/guides/guides.json', import.meta.url), 'utf8')).console;
const list = JSON.parse(fs.readFileSync(new URL('../src/components/guide/guides.json', import.meta.url), 'utf8'));
const body = JSON.stringify(Object.fromEntries(Object.entries(list).filter(([, entry]) => entry.kind !== 'legacy').map(([id]) => [id, { ...recorded, captionsNarrow: recorded.captions }])));
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width, height: 844 }, locale: 'ko-KR', reducedMotion: 'reduce' });
const page = await context.newPage();
await page.route('**/guides/guides.json', (request) => request.fulfill({ contentType: 'application/json', body }));
await page.goto(`${base}/${path}?lng=ko`, { waitUntil: 'networkidle' });
await page.waitForTimeout(1200);
const rows = await page.evaluate(() => {
  const out = [];
  const walk = (el, depth) => {
    if (depth > 4) return;
    for (const child of el.children) {
      const r = child.getBoundingClientRect();
      if (r.height === 0) continue;
      out.push(`${'  '.repeat(depth)}${child.tagName.toLowerCase()}.${String(child.className).split(' ')[0].slice(0, 34)} top ${Math.round(r.top + window.scrollY)} h ${Math.round(r.height)}`);
      if (depth < 3) walk(child, depth + 1);
    }
  };
  walk(document.querySelector('main'), 0);
  const foot = document.querySelector('[data-zone="actions"]');
  out.push(`foot top ${Math.round(foot.getBoundingClientRect().top + window.scrollY)} h ${Math.round(foot.getBoundingClientRect().height)}`);
  out.push(`doc ${document.documentElement.scrollHeight}`);
  return out;
});
console.log(rows.join('\n'));
await browser.close();
