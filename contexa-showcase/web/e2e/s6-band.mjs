// The place band on every route (common-1, U-8): one screen of each act and of the concept path, opened at the phone
// and tablet widths in Korean and English, checked for a band part covering another (the tabs running under the
// difference badge), page overflow and serious axe violations. No run is sent: the band depends only on the place.
// Usage: node e2e/s6-band.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { inspect } from './screenCheck.mjs';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:5180';
mkdirSync(out, { recursive: true });

/** The first and the last screen of each act (the most and fewest steps behind), and two of the concept path. */
const SCREENS = [
  ['act1-first', '/try/attacker/scene'],
  ['act1-last', '/try/attacker/after'],
  ['act2-first', '/try/owner/scene'],
  ['act2-last', '/try/follow'],
  ['act3-first', '/intro/learning'],
  ['act3-last', '/try/summary/learning'],
  ['act4-first', '/intro/approaches'],
  ['act4-last', '/try/summary/adopt'],
  ['intro-first', '/intro/concept?route=intro'],
  ['intro-last', '/try/summary/adopt?route=intro'],
];
const WIDTHS = [360, 390, 768];

const browser = await chromium.launch();
const report = [];
for (const language of ['ko', 'en']) {
  const context = await browser.newContext({ viewport: { width: 390, height: 900 }, locale: language });
  const page = await context.newPage();
  for (const [name, path] of SCREENS) {
    const separator = path.includes('?') ? '&' : '?';
    await page.goto(`${base}${path}${separator}lng=${language}`, { waitUntil: 'networkidle' });
    for (const width of WIDTHS) {
      await page.setViewportSize({ width, height: 900 });
      await page.waitForTimeout(300);
      await page.screenshot({
        path: join(out, `${name}-${language}-${width}.png`),
        clip: { x: 0, y: 0, width, height: 420 },
      });
      const result = await inspect(page);
      report.push({
        language,
        name,
        width,
        overflow: result.overflow,
        bandOverlap: result.bandOverlap,
        serious: result.serious,
      });
    }
  }
  await context.close();
}
await browser.close();
writeFileSync(join(out, 'band-report.json'), JSON.stringify(report, null, 1));
const bad = report.filter((row) => row.bandOverlap || row.overflow || row.serious.length);
for (const row of bad) {
  console.log(
    `${row.language} ${row.name} ${row.width}: overlap ${row.bandOverlap}, overflow ${row.overflow}, axe ${JSON.stringify(row.serious)}`,
  );
}
console.log(`band screens checked ${report.length}, problems ${bad.length}`);
