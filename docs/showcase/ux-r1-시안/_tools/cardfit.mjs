// Every element must stay inside its card, and the page must not scroll sideways.
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';
const DIR = process.env.MOCK;
const files = process.env.FILES ? process.env.FILES.split(',') : fs.readdirSync(DIR).filter((f) => f.startsWith('s-') && f.endsWith('.html'));
const widths = (process.env.WIDTHS ?? '1440,390').split(',').map(Number);
const browser = await chromium.launch();
for (const width of widths) {
  const page = await (await browser.newContext({ viewport: { width, height: 900 } })).newPage();
  for (const f of files) {
    await page.goto('file:///' + path.join(DIR, f).split(path.sep).join('/'), { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    const bad = await page.evaluate(() => {
      const out = [];
      for (const card of document.querySelectorAll('.card')) {
        const cr = card.getBoundingClientRect();
        for (const e of card.querySelectorAll('*')) {
          const r = e.getBoundingClientRect();
          if (r.width === 0) continue;
          let p = e.parentElement, scrolls = false;
          while (p && p !== card) { const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden') { scrolls = true; break; } p = p.parentElement; }
          if (!scrolls && r.right > cr.right + 1) { out.push(`${e.tagName.toLowerCase()} +${Math.round(r.right - cr.right)}px "${(e.textContent || '').trim().slice(0, 24)}"`); break; }
        }
      }
      if (document.documentElement.scrollWidth > document.documentElement.clientWidth) out.push('PAGE SCROLLS SIDEWAYS');
      return out;
    });
    console.log(`${width} ${f}: ${bad.length ? bad.join(' | ') : 'ok'}`);
  }
}
await browser.close();
