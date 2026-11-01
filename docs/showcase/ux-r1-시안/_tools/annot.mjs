import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';
const DIR = process.env.MOCK; const spec = JSON.parse(fs.readFileSync(process.env.SPEC, 'utf8'));
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
const out = {};
for (const [f, sels] of Object.entries(spec)) {
  await page.goto('file:///' + path.join(DIR, f).split(path.sep).join('/'), { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  out[f] = await page.evaluate((sels) => {
    const r = { pageH: document.documentElement.scrollHeight, rects: {} };
    for (const s of sels) { const e = document.querySelector(s); if (!e) { r.rects[s] = null; continue; } const b = e.getBoundingClientRect(); r.rects[s] = [b.left, b.top + scrollY, b.width, b.height]; }
    return r;
  }, sels);
}
fs.writeFileSync(process.env.OUT, JSON.stringify(out, null, 1));
await browser.close();
