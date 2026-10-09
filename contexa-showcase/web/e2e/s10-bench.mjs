// S10 check on the real stack (C-3, C-4, C-5, C-16): the benchmark's four views and its three windows in Korean and
// English (the summary, the group the rules were not written for, the case list with its filter and its operations
// tab, judgment and timing, the limits; the approach card, how it was measured, a case). Every capture is taken at
// 390, 768, 1024 and 1440 px; a window's limits are counted inside the window.
// Usage: node e2e/s10-bench.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { capture } from './screenCheck.mjs';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:5180';
mkdirSync(out, { recursive: true });

const benchmark = await (await fetch(`${base}/api/benchmark`)).json();
const wrongCase = benchmark.cases.find((row) => row.contexaWrong)?.key ?? benchmark.cases[0].key;
const suite = benchmark.suites[0]?.suite ?? null;

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

  await open('bench-summary', '/benchmark');
  if (suite) {
    await open('bench-summary-suite', `/benchmark?suite=${suite}`);
  }
  await open('bench-approach', '/benchmark?modal=approach&control=D', 'dialog[open]');
  await open('bench-method', '/benchmark?modal=method', 'dialog[open]');
  await open('bench-cases', '/benchmark/cases');
  await open('bench-cases-wrong', '/benchmark/cases?wrong=1');
  await open('bench-cases-normal', '/benchmark/cases?tab=normal');
  await open('bench-cases-ops', '/benchmark/cases?tab=ops');
  await open('bench-case', `/benchmark/cases?modal=case&case=${wrongCase}`, 'dialog[open]');
  await open('bench-judgment', '/benchmark/judgment');
  await open('bench-limits', '/benchmark/limits');
  values.push({ language, screen: 'errors', errors });
  await context.close();
}
await browser.close();

writeFileSync(join(out, 'report.json'), JSON.stringify({ wrongCase, suite, report, values }, null, 2));
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
