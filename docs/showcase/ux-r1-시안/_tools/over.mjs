import path from 'node:path';
import { chromium } from '@playwright/test';
const DIR = process.env.MOCK;
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
await context.addInitScript(() => document.documentElement.classList.add('phone'));
const page = await context.newPage();
for (const f of process.env.FILES.split(',')) {
  await page.goto('file:///' + path.join(DIR, f).split(path.sep).join('/'), { waitUntil: 'networkidle' });
  await page.waitForTimeout(800);
  const o = await page.evaluate(() => {
    const lim = document.documentElement.clientWidth;
    return [...document.querySelectorAll('body *')].filter((e) => e.getBoundingClientRect().right > lim + 0.5 && e.getBoundingClientRect().width > 0)
      .slice(0, 8).map((e) => `${e.tagName.toLowerCase()}.${String(e.className?.baseVal ?? e.className).slice(0, 30)} r=${Math.round(e.getBoundingClientRect().right)} ${(e.textContent || '').trim().slice(0, 30)}`);
  });
  console.log(f, o.join('\n  '));
}
await browser.close();
