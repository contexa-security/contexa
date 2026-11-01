// Same measures as the live-site audit, over the mockups (ko, 1440).
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';
const DIR = process.env.MOCK;
const files = fs.readdirSync(DIR).filter((f) => f.startsWith('s-') && f.endsWith('.html') && !f.includes('-en'));
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
const all = { sizes: {}, combos: {}, radii: {}, btnH: {}, folds: 0, details: 0 };
for (const f of files) {
  await page.goto('file:///' + path.join(DIR, f).split(path.sep).join('/'), { waitUntil: 'networkidle' });
  await page.waitForTimeout(300);
  const m = await page.evaluate(() => {
    const out = { sizes: {}, combos: {}, radii: {}, btnH: {}, details: document.querySelectorAll('details').length };
    for (const e of document.querySelectorAll('main *, aside *, header *')) {
      const cs = getComputedStyle(e);
      const own = [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
      if (own) { out.sizes[cs.fontSize] = (out.sizes[cs.fontSize] || 0) + 1; const k = cs.fontSize + '/' + cs.fontWeight; out.combos[k] = (out.combos[k] || 0) + 1; }
      const r = cs.borderTopLeftRadius; if (r !== '0px' && (cs.backgroundColor !== 'rgba(0, 0, 0, 0)' || cs.borderTopWidth !== '0px')) out.radii[r] = (out.radii[r] || 0) + 1;
      if (e.matches('button, .btn, a.btn')) { const h = Math.round(e.getBoundingClientRect().height); out.btnH[h] = (out.btnH[h] || 0) + 1; if (h === 34 || h === 28) out.btnH[h + ':' + (e.className || e.tagName).toString().slice(0, 30)] = 1; }
    }
    return out;
  });
  for (const k of ['sizes', 'combos', 'radii', 'btnH']) for (const [a, b] of Object.entries(m[k])) all[k][a] = (all[k][a] || 0) + b;
  all.details += m.details;
}
const fmt = (o) => Object.entries(o).sort((a, b) => parseFloat(a[0]) - parseFloat(b[0])).map(([a, b]) => `${a} x${b}`).join(', ');
console.log('screens', files.length);
console.log('font sizes', Object.keys(all.sizes).length, ':', fmt(all.sizes));
console.log('size/weight combos', Object.keys(all.combos).length, ':', fmt(all.combos));
console.log('radii', Object.keys(all.radii).length, ':', fmt(all.radii));
console.log('button heights', Object.keys(all.btnH).length, ':', fmt(all.btnH));
console.log('folds (details)', all.details);
await browser.close();
