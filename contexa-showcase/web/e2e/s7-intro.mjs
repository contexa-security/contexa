// S7 check on the real stack (C-3, C-4, C-5, C-16): the concept path in Korean and English. The introduction, the
// problem in its two layers, how we compare (and its window on what the runs share), the order of the tries, and one
// screen both routes share seen on the concept path. Every screen is captured at 390, 768, 1024 and 1440 px and checked
// like the acts; the values the screens read are kept for comparison with the API. No run is sent.
// Usage: node e2e/s7-intro.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { capture, inspect } from './screenCheck.mjs';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:5180';
const DICTIONARIES = {
  ko: JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8')),
  en: JSON.parse(readFileSync('src/i18n/en.json', 'utf-8')),
};
mkdirSync(out, { recursive: true });

const SCREENS = [
  ['g1-start', '/intro'],
  ['g2-concept', '/intro/concept?route=intro'],
  ['g2-concept-layer2', '/intro/concept?route=intro&layer=2'],
  ['g3-five-intro', '/intro/approaches?route=intro'],
  ['g4-compare', '/intro/compare'],
  ['g5-order', '/intro/order'],
];

const browser = await chromium.launch();
const report = [];
const values = [];
for (const language of ['ko', 'en']) {
  const m = DICTIONARIES[language];
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    locale: language,
    reducedMotion: 'reduce',
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 300)));
  for (const [name, path] of SCREENS) {
    const separator = path.includes('?') ? '&' : '?';
    await page.goto(`${base}${path}${separator}lng=${language}`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(600);
    values.push({
      language,
      screen: name,
      heading: await page.locator('h1').innerText(),
      main: (await page.locator('main').innerText()).slice(0, 900),
    });
    await capture(page, out, language, name, report);
    if (name === 'g4-compare') {
      await page.getByRole('button', { name: m['compare.same'] }).click();
      await page.getByRole('dialog').waitFor();
      await page.waitForTimeout(500);
      values.push({ language, screen: 'g4-window', text: await page.getByRole('dialog').innerText() });
      for (const width of [390, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        await page.waitForTimeout(300);
        await page.screenshot({ path: join(out, `g4-window-${language}-${width}.png`) });
        report.push({ language, name: 'g4-window', width, ...(await inspect(page)) });
      }
      await page.setViewportSize({ width: 1440, height: 900 });
      await page.keyboard.press('Escape');
    }
  }
  values.push({ language, screen: 'errors', errors });
  await context.close();
}
await browser.close();
writeFileSync(join(out, 's7-report.json'), JSON.stringify({ report, values }, null, 1));
for (const row of report.filter((entry) => entry.width === 1440)) {
  console.log(
    `${row.language} ${row.name}: main buttons ${row.limits?.primaries}, numbers ${row.limits?.numbers}, english ${JSON.stringify(row.language === 'ko' ? row.limits?.english : [])}`,
  );
}
for (const row of report) {
  if (row.overflow || row.bandOverlap || row.singleLetter.length || row.serious.length) {
    console.log(
      `${row.language} ${row.name} ${row.width}: overflow ${row.overflow}, band overlap ${row.bandOverlap}, single-letter ${JSON.stringify(row.singleLetter)}, axe ${JSON.stringify(row.serious)}`,
    );
  }
}
console.log(`screens checked ${report.length}`);
