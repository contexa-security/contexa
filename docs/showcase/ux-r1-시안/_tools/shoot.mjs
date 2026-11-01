// Screenshots the UX-R1 mockups: node --input-type=module < shoot.mjs  (cwd = contexa-showcase/web for Playwright)
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';
const DIR = process.env.MOCK;
const files = (process.env.FILES ? process.env.FILES.split(',') : fs.readdirSync(DIR).filter((f) => f.startsWith('s-') && f.endsWith('.html')));
const widths = (process.env.WIDTHS ?? '1440,390').split(',').map(Number);
const browser = await chromium.launch();
for (const width of widths) {
  const context = await browser.newContext({ viewport: { width, height: width <= 400 ? 844 : 900 }, deviceScaleFactor: 2 });
  const page = await context.newPage();
  for (const f of files) {
    const query = process.env.THEME === 'light' ? '?theme=light' : '';
    await page.goto('file:///' + path.join(DIR, f).split(path.sep).join('/') + query, { waitUntil: 'networkidle' });
    await page.waitForFunction(() => document.documentElement.dataset.ready === '1', null, { timeout: 15000 }).catch(() => {});
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(300);
    const view = process.env.FULL === '0';
    if (process.env.SCROLL) await page.evaluate((y) => window.scrollTo(0, y), Number(process.env.SCROLL));
    const name = f.replace('.html', '') + `-${width}${process.env.THEME === 'light' ? '-light' : ''}${view ? '-view' + (process.env.SCROLL ? '-' + process.env.SCROLL : '') : ''}.png`;
    await page.screenshot({ path: path.join(DIR, 'out', name), fullPage: !view });
    const over = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    console.log(name, over ? 'OVERFLOW' : 'ok');
  }
  await context.close();
}
await browser.close();
