// S6 check on the real stack (C-2, C-3, C-4, C-5, C-16): act 4 in Korean and English. The visitor sends try 1 once so
// "what you did" has a run of their own, then the five approaches (and two of their settings windows), where they sit
// (and the code window), the dilemma, what you did, the understanding check (a question and the scored result), the
// core value and what changes with adoption. Every screen is captured at 390, 768, 1024 and 1440 px and checked like
// acts 1 to 3; the values the screens read are kept for comparison with the API.
// Usage: node e2e/s6-act4.mjs <out dir> [base url]
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

const api = (page, path) => page.evaluate((p) => fetch(p).then((r) => (r.ok ? r.json() : null)), path);
const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** A window opened over a screen: captured at the phone and the widest width, with the same checks. */
async function captureWindow(page, name, language, report) {
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await page.waitForTimeout(300);
    await page.screenshot({ path: join(out, `${name}-${language}-${width}.png`), fullPage: false });
    report.push({ language, name, width, ...(await inspect(page)) });
  }
  await page.setViewportSize({ width: 1440, height: 900 });
}

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

  // Try 1 sent without a call: the run "what you did" shows.
  await page.goto(`${base}/try/attacker/predict?lng=${language}`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: m['e1.predict.sendWithout'] }).click();
  await page.waitForURL(/\/try\/attacker\/run/, { timeout: 30_000 });
  await page.getByRole('link', { name: m['e1.next.result'] }).waitFor({ timeout: 240_000 });

  await page.goto(`${base}/intro/approaches?lng=${language}`, { waitUntil: 'networkidle' });
  await capture(page, out, language, 'g3-five', report);
  for (const control of ['A', 'B', 'C1', 'C2', 'D']) {
    await page
      .getByRole('list', { name: m['approaches.title'] })
      .getByRole('button', { name: new RegExp(`^${escape(m[`control.${control}.name`])}`) })
      .click();
    await page.getByRole('dialog').waitFor();
    await page.waitForTimeout(500);
    values.push({
      language,
      screen: `settings-${control}`,
      text: await page.getByRole('dialog').innerText(),
    });
    await captureWindow(page, `g3-settings-${control}`, language, report);
    await page.keyboard.press('Escape');
  }

  await page.goto(`${base}/intro/approaches/where?lng=${language}`, { waitUntil: 'networkidle' });
  await capture(page, out, language, 'g-where', report);
  await page.getByRole('button', { name: m['where.code'] }).click();
  await page.getByRole('dialog').waitFor();
  await captureWindow(page, 'g-where-code', language, report);
  await page.keyboard.press('Escape');

  await page.goto(`${base}/try/summary/dilemma?lng=${language}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(800);
  values.push({
    language,
    screen: 'dilemma',
    heading: await page.locator('h1').innerText(),
    figures: await page.locator('main section[aria-labelledby^="dilemma-"] dd').allInnerTexts(),
    conclusion: await page.locator('main p').last().innerText(),
  });
  await capture(page, out, language, 'dilemma', report);

  await page.goto(`${base}/try/summary/recap?lng=${language}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(800);
  values.push({
    language,
    screen: 'recap',
    rows: await page.locator('main table tbody tr').allInnerTexts(),
    journeyRuns: (await api(page, '/api/journey'))?.runs,
  });
  await capture(page, out, language, 'recap', report);

  await page.goto(`${base}/try/summary/quiz?lng=${language}`, { waitUntil: 'networkidle' });
  await capture(page, out, language, 'quiz', report);
  await page.getByLabel(m['quiz.Q1.option.USUAL_AND_COMPANY'], { exact: true }).check();
  await page.getByRole('button', { name: m['quiz.nextQuestion'] }).click();
  await page.getByLabel(m['quiz.Q2.option.PASSWORD'], { exact: true }).check();
  await page.getByRole('button', { name: m['quiz.nextQuestion'] }).click();
  await page.getByLabel(m['quiz.Q3.option.SYNC'], { exact: true }).check();
  await page.getByRole('button', { name: m['quiz.score'] }).click();
  await page.getByRole('heading', { level: 2 }).waitFor();
  values.push({
    language,
    screen: 'quiz-result',
    text: await page.locator('main section').last().innerText(),
  });
  await capture(page, out, language, 'quiz-result', report);

  await page.goto(`${base}/try/summary/value?lng=${language}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(800);
  values.push({
    language,
    screen: 'value',
    cards: await page.getByRole('list', { name: m['value.title'] }).getByRole('listitem').allInnerTexts(),
  });
  await capture(page, out, language, 'value', report);

  await page.goto(`${base}/try/summary/adopt?lng=${language}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(800);
  values.push({
    language,
    screen: 'adopt-change',
    cells: await page.locator(`main dl[aria-label="${m['adoptChange.title']}"] > div`).allInnerTexts(),
  });
  await capture(page, out, language, 'adopt-change', report);

  values.push({ language, screen: 'errors', errors });
  await context.close();
}
await browser.close();
writeFileSync(join(out, 's6-report.json'), JSON.stringify({ report, values }, null, 1));
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
console.log(JSON.stringify(values, null, 1).slice(0, 8000));
