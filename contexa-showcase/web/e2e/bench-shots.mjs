// Shoots the benchmark screens as a visitor sees them, for the benchmark redesign's survey (docs/showcase): every
// benchmark address at the given widths and languages, the whole page, into <outDir>/<page>-<language>-<width>.png.
// Usage: node e2e/bench-shots.mjs <outDir> [--base <url>] [--widths 1440,390] [--languages ko] [--setting <hash>]
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { chromium } from '@playwright/test';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
const out = args[0];
if (!out || out.startsWith('--')) {
  console.error('usage: node e2e/bench-shots.mjs <outDir> [--base <url>] [--widths 1440,390] [--languages ko]');
  process.exit(2);
}
const base = option('--base', 'http://127.0.0.1:19180');
const widths = option('--widths', '1440,390').split(',').map(Number);
const languages = option('--languages', 'ko').split(',');
const setting = option('--setting', null);
const PAGES = [
  ['summary', '/benchmark'],
  ['approaches', '/benchmark/approaches'],
  ['cases', '/benchmark/cases'],
  ['judgment', '/benchmark/judgment'],
  ['reasoning', '/benchmark/reasoning'],
  ['limits', '/benchmark/limits'],
];

mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
try {
  for (const language of languages) {
    for (const width of widths) {
      const context = await browser.newContext({ viewport: { width, height: 900 }, locale: language });
      const page = await context.newPage();
      for (const [name, path] of PAGES) {
        await page.goto(`${base}${path}?lng=${language}${setting ? `&setting=${setting}` : ''}`, { waitUntil: 'networkidle' });
        await page.waitForTimeout(800);
        const file = join(out, `${name}-${language}-${width}.png`);
        await page.screenshot({ path: file, fullPage: true });
        const height = await page.evaluate(() => document.documentElement.scrollHeight);
        console.log(`${name}-${language}-${width} ${height}px`);
      }
      await context.close();
    }
  }
} finally {
  await browser.close();
}
