// S11 check on the real stack (15.3): a run the visitor sent stays on the try's steps after the portal restarts. The
// portal keeps the current run in memory only, so the steps draw the latest finished run of the case from the
// visitor's journey (database) once it is gone.
// Usage: node e2e/s11-restart.mjs send <out dir> [base url]   sends try 1 once (one real run) and keeps the cookies
//        node e2e/s11-restart.mjs view <out dir> [base url]   after the portal restarted: the API and the four steps
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const phase = process.argv[2];
const out = process.argv[3];
const base = process.argv[4] ?? 'http://127.0.0.1:19180';
const dictionaries = {
  ko: JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8')),
  en: JSON.parse(readFileSync('src/i18n/en.json', 'utf-8')),
};
const state = join(out, 'state.json');
mkdirSync(out, { recursive: true });

const browser = await chromium.launch();
const viewport = { width: 1440, height: 900 };

async function read(page, path) {
  return page.evaluate(async (url) => {
    const response = await fetch(url, { credentials: 'include' });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null };
  }, path);
}

if (phase === 'send') {
  const context = await browser.newContext({ viewport, locale: 'ko', reducedMotion: 'reduce' });
  const page = await context.newPage();
  await page.goto(`${base}/try/attacker/predict?lng=ko`, { waitUntil: 'networkidle' });
  await page.getByText(dictionaries.ko['e1.predict.CHALLENGE'], { exact: true }).first().click();
  await page.locator('main [data-main]').click();
  await page.waitForURL(/\/try\/attacker\/run/);
  await page.getByRole('link', { name: dictionaries.ko['e1.next.result'] }).waitFor({ timeout: 300_000 });
  await page.waitForTimeout(800);
  await page.screenshot({ path: join(out, 'send-ko-1440-ended.png'), fullPage: true });
  const current = await read(page, '/api/live/runs/current');
  writeFileSync(join(out, 'send-current.json'), JSON.stringify(current, null, 2));
  await context.storageState({ path: state });
  console.log(JSON.stringify({ runId: current.body?.runId ?? null, status: current.body?.status ?? null }));
} else if (phase === 'view') {
  const report = { api: {}, steps: [] };
  for (const language of ['ko', 'en']) {
    const context = await browser.newContext({ viewport, locale: language, reducedMotion: 'reduce', storageState: state });
    const page = await context.newPage();
    await page.goto(`${base}/?lng=${language}`, { waitUntil: 'networkidle' });
    if (language === 'ko') {
      report.api.current = await read(page, '/api/live/runs/current');
      const journey = await read(page, '/api/journey');
      report.api.journeyRuns = journey.status === 200
        ? journey.body.runs.filter((line) => line.scenarioKey === 'A3')
        : journey;
    }
    const m = dictionaries[language];
    for (const step of ['run', 'result', 'reason', 'after']) {
      await page.goto(`${base}/try/attacker/${step}?lng=${language}`, { waitUntil: 'networkidle' });
      await page.locator('main h1').first().waitFor({ timeout: 20_000 });
      await page.waitForTimeout(1500);
      const heading = await page.locator('main h1').first().innerText();
      // The run the step draws, as its first source mark names it once opened.
      const mark = page.locator('main').getByRole('button', { name: m['source.button'], exact: true }).first();
      if ((await mark.count()) > 0) {
        await mark.click();
      }
      const text = await page.locator('main').innerText();
      const runIds = [...new Set(text.match(/run-[0-9a-f]{12}/g) ?? [])];
      report.steps.push({
        language,
        step,
        heading,
        notSent: text.includes(m['e1.run.notSent']),
        loading: (await page.locator('main [role="status"]').count()) > 0 && !heading,
        runIds,
      });
      await page.screenshot({ path: join(out, `view-${step}-${language}-1440.png`), fullPage: true });
    }
    await context.close();
  }
  writeFileSync(join(out, 'view-report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report.steps.map(({ language, step, heading, notSent }) => ({ language, step, heading, notSent }))));
} else {
  console.error('phase: send | view');
  process.exitCode = 2;
}
await browser.close();
