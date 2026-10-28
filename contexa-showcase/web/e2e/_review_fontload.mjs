// 일회용: 주 흐름 화면의 첫 화면 글자를 크기와 대비로 셉니다(코드 변경 없음). 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const route = JSON.parse(fs.readFileSync(new URL('../src/journey/route.json', import.meta.url), 'utf8'));
const sizes = [['d', 1440, 900], ['m', 390, 844]];
const browser = await chromium.launch();
const rows = [];
for (const [tag, width, height] of sizes) {
  const context = await browser.newContext({ viewport: { width, height }, locale: 'ko-KR', reducedMotion: 'reduce' });
  const page = await context.newPage();
  for (const screen of route) {
    await page.goto(`${process.env.BASE ?? 'http://127.0.0.1:19180'}${screen.path}?lng=ko`, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(500);
    const m = await page.evaluate(() => {
      const vh = window.innerHeight;
      const parse = (c) => { const x = c.match(/[\d.]+/g).map(Number); return { r: x[0], g: x[1], b: x[2], a: x.length > 3 ? x[3] : 1 }; };
      const lum = ({ r, g, b }) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
      const backgroundOf = (el) => {
        let layers = [];
        for (let e = el; e; e = e.parentElement) {
          const c = parse(getComputedStyle(e).backgroundColor);
          if (c.a > 0) { layers.push(c); if (c.a >= 1) break; }
        }
        let base = { r: 5, g: 10, b: 25, a: 1 };
        for (const c of layers.reverse()) base = { r: c.r * c.a + base.r * (1 - c.a), g: c.g * c.a + base.g * (1 - c.a), b: c.b * c.a + base.b * (1 - c.a), a: 1 };
        return base;
      };
      const contrast = (fg, bg) => { const a = lum(fg), b = lum(bg); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); };
      const out = { chars: 0, under14: 0, under16: 0, under18: 0, lowContrast: 0, minSize: 99, sizes: {} };
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        const text = node.textContent.replace(/\s+/g, '');
        if (!text) continue;
        const el = node.parentElement;
        if (!el || el.closest('script,style,noscript')) continue;
        const range = document.createRange();
        range.selectNodeContents(node);
        const r = range.getBoundingClientRect();
        if (r.width === 0 || r.height === 0 || r.top >= vh || r.bottom <= 0) continue;
        const style = getComputedStyle(el);
        if (style.visibility === 'hidden' || style.display === 'none') continue;
        const size = parseFloat(style.fontSize);
        const n = text.length;
        out.chars += n;
        if (size < 14) out.under14 += n;
        if (size < 16) out.under16 += n;
        if (size < 18) out.under18 += n;
        out.minSize = Math.min(out.minSize, size);
        out.sizes[Math.round(size)] = (out.sizes[Math.round(size)] || 0) + n;
        const fg = parse(style.color);
        const ratio = contrast({ r: fg.r, g: fg.g, b: fg.b }, backgroundOf(el));
        const need = size >= 24 || (size >= 18.66 && Number(style.fontWeight) >= 700) ? 3 : 4.5;
        if (ratio < need) out.lowContrast += n;
      }
      return out;
    });
    rows.push({ tag, number: screen.number, path: screen.path, type: screen.type, ...m });
  }
  await context.close();
}
await browser.close();
fs.writeFileSync(process.argv[2], JSON.stringify(rows, null, 1));
console.log('ok', rows.length);
