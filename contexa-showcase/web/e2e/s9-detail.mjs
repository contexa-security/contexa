// S9 check on the real stack (C-3, C-4, C-5, C-16): the decision details window in Korean and English, each of its
// six tabs for a measured model decision, the summary of a request an earlier decision refused, and the stored real
// record of a recorded pair and of a measured case; the first screen again, since its replay moved to the shared stage.
// Every capture is taken at 390, 768, 1024 and 1440 px; the window's limits are counted inside the window.
// Usage: node e2e/s9-detail.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { capture } from './screenCheck.mjs';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:5180';
mkdirSync(out, { recursive: true });

const TABS = ['summary', 'received', 'process', 'prompt', 'answer', 'original'];
const benchmark = await (await fetch(`${base}/api/benchmark`)).json();
const runOf = (key) => benchmark.cases.find((row) => row.key === key)?.runIds[0];
const decided = runOf('A3');
const refused = runOf('A6');

const browser = await chromium.launch();
const report = [];
const values = [];
for (const language of ['ko', 'en']) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    locale: language,
    reducedMotion: 'reduce',
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 300)));
  const open = async (name, path, root = 'main') => {
    await page.goto(`${base}${path}${path.includes('?') ? '&' : '?'}lng=${language}`, {
      waitUntil: 'networkidle',
    });
    await page.waitForTimeout(700);
    const heading = root === 'main' ? 'main h1' : 'dialog[open] h2';
    values.push({ language, screen: name, heading: await page.locator(heading).first().innerText(), url: page.url() });
    await capture(page, out, language, name, report, root);
  };

  for (const tab of TABS) {
    await open(`detail-${tab}`, `/run/${decided}/detail?step=1&tab=${tab}`, 'dialog[open]');
  }
  await open('detail-refused', `/run/${refused}/detail?step=2`, 'dialog[open]');
  await open('replay-pair', '/replay/A3?from=%2Ftry%2Fattacker%2Fpredict');
  await open('replay-case', '/replay/A6T?from=%2Ftry%2Fstack');
  await open('hook', '/');
  values.push({ language, screen: 'errors', errors });
  await context.close();
}
await browser.close();

writeFileSync(join(out, 'report.json'), JSON.stringify({ decided, refused, report, values }, null, 2));
const problems = report.filter(
  (entry) =>
    entry.overflow > 0 ||
    entry.bandOverlap > 0 ||
    entry.singleLetter.length > 0 ||
    entry.serious.length > 0 ||
    (entry.limits &&
      (entry.limits.primaries > 1 ||
        entry.limits.numbers > 20 ||
        (entry.language === 'ko' && entry.limits.english.length > 0))),
);
console.log(`${report.length} captures, ${problems.length} with problems`);
for (const entry of problems) {
  console.log(JSON.stringify(entry));
}
for (const entry of values.filter((value) => value.screen === 'errors' && value.errors.length > 0)) {
  console.log(JSON.stringify(entry));
}
