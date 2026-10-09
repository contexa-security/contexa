// S12 C-13 on the real stack: every address with a first-screen rule (src/firstScreens.ts) and the other entry
// addresses, opened as a first load in a fresh page at 1440 x 900 in Korean by the visitor who sent try 1 and try 2.
// For each: requests that failed, a URL read twice (a preload the application did not reuse), the browser's warning
// that a preload went unused, and console errors. Every row should be empty.
// Usage: node e2e/s12-first-load.mjs <out dir> <visitor state json> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const state = process.argv[3];
const base = process.argv[4] ?? 'http://127.0.0.1:19180';
mkdirSync(out, { recursive: true });

const ADDRESSES = [
  '/', '/try/attacker/scene', '/try/attacker/compare', '/try/attacker/predict', '/try/attacker/result',
  '/try/attacker/reason', '/try/attacker/after', '/try/owner/scene?mode=async', '/try/owner/compare',
  '/try/owner/result', '/try/timing/concept', '/try/timing/try', '/try/follow', '/try/follow/end',
  '/intro/how/rules', '/intro/learning', '/intro/learning/learned', '/intro/how', '/try/prompt', '/try/stack',
  '/try/summary/learning', '/try/summary/learning/end', '/intro/approaches', '/intro/approaches/where',
  '/try/summary/dilemma', '/try/summary/recap', '/try/summary/quiz', '/try/summary/value', '/try/summary/adopt',
  '/intro', '/intro/concept', '/intro/compare', '/intro/order', '/lab', '/lab/case?case=A3T',
  '/lab/change?case=A3T&field=approval', '/lab/before?case=A3T&approval=false', '/lab/send?case=A3T&approval=false',
  '/lab/rules', '/benchmark', '/benchmark/cases', '/adopt', '/privacy',
];

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko', storageState: state });
const report = [];
for (const address of ADDRESSES) {
  const page = await context.newPage();
  const asked = new Map();
  const failed = [];
  const messages = [];
  page.on('request', (request) => {
    const url = request.url();
    if (url.startsWith(base)) {
      asked.set(url, (asked.get(url) ?? 0) + 1);
    }
  });
  page.on('response', (response) => {
    if (response.status() >= 400 && response.url().startsWith(base) && !response.url().endsWith('/api/live/runs/current')) {
      failed.push(`${response.status()} ${response.url().slice(base.length)}`);
    }
  });
  page.on('requestfailed', (request) => failed.push(`failed ${request.url().slice(base.length)}`));
  page.on('console', (message) => {
    if (message.type() === 'error' || /preload/i.test(message.text())) {
      messages.push(`${message.type()} ${message.text().slice(0, 160)}`);
    }
  });
  await page.goto(`${base}${address}${address.includes('?') ? '&' : '?'}lng=ko`, { waitUntil: 'networkidle' });
  await page.locator('main h1, main h2').first().waitFor({ timeout: 20_000 });
  // The browser warns about an unused preload a few seconds after the load.
  await page.waitForTimeout(3500);
  const twice = [...asked].filter(([url, times]) => times > 1 && !url.includes('/api/journey')).map(([url, times]) => `${times}x ${url.slice(base.length)}`);
  const preloaded = await page.evaluate(() =>
    [...document.querySelectorAll('link[rel="modulepreload"], link[rel="preload"]')].length,
  );
  report.push({ address, preloaded, failed, twice, messages });
  console.log(`${address.padEnd(42)} preloaded ${String(preloaded).padStart(2)} failed ${failed.length} twice ${twice.length} messages ${messages.length}`);
  await page.close();
}
writeFileSync(join(out, 'first-load.json'), JSON.stringify(report, null, 2));
await browser.close();
