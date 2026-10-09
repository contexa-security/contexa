// S11 check on the real stack: the run screen on a phone (390 px), where the nine-cell strip holds the bottom and the
// main button sits over it. Sends try 1 once (one real run) and captures the screen while it runs and when it ended.
// Usage: node e2e/s11-run.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:5180';
const m = JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8'));
mkdirSync(out, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 390, height: 844 }, locale: 'ko', reducedMotion: 'reduce' });
await page.goto(`${base}/try/attacker/predict?lng=ko`, { waitUntil: 'networkidle' });
await page.getByText(m['e1.predict.CHALLENGE'], { exact: true }).first().click();
await page.locator('main [data-main]').click();
await page.waitForURL(/\/try\/attacker\/run/);
await page.waitForTimeout(2500);
await page.screenshot({ path: join(out, 'run-ko-390-running.png') });
await page.getByRole('link', { name: m['e1.next.result'] }).waitFor({ timeout: 240_000 });
await page.waitForTimeout(800);
await page.screenshot({ path: join(out, 'run-ko-390-ended.png') });
const layout = await page.evaluate(() => {
  const strip = document.querySelector('[data-inside-strip]')?.getBoundingClientRect();
  const main = document.querySelector('main [data-main]')?.getBoundingClientRect();
  return { strip: strip && { top: strip.top, bottom: strip.bottom }, main: main && { top: main.top, bottom: main.bottom } };
});
writeFileSync(join(out, 'run-layout.json'), JSON.stringify(layout, null, 2));
console.log(JSON.stringify(layout));
await browser.close();
