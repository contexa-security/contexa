// S12 C-6 and C-2 on the real stack: one run read on every screen that shows it. For the visitor's own try 1 and try 2
// runs: the result table, the decision details' summary and "what you did"; for one measured run of the benchmark: the
// case window and the decision details. Each place's decision word and right-or-wrong mark are written down with the
// portal's score and anatomy of the same run; s12-same-run-db.py compares them with the database.
// Usage: node e2e/s12-same-run.mjs <out dir> <visitor state json> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const state = process.argv[3];
const base = process.argv[4] ?? 'http://127.0.0.1:19180';
const m = JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8'));
mkdirSync(out, { recursive: true });

const VERDICT_WORDS = ['allow', 'verify', 'review', 'block'].map((key) => m[`verdict.${key}`]);
const wordsIn = (text) => VERDICT_WORDS.filter((word) => text.includes(word));
const markIn = (text) => (text.includes(m['mark.right']) ? 'right' : text.includes(m['mark.wrong']) ? 'wrong' : null);

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko', storageState: state });
const page = await context.newPage();
const api = (path) => page.evaluate((target) => fetch(target).then((r) => (r.ok ? r.json() : null)), path);
await page.goto(`${base}/?lng=ko`, { waitUntil: 'networkidle' });

const journey = await api('/api/journey');
const latest = (key) =>
  [...journey.runs].reverse().find((line) => line.scenarioKey === key && line.status === 'COMPLETED')?.runId ?? null;
const report = [];

async function detailSummary(runId) {
  await page.goto(`${base}/run/${runId}/detail?step=1&lng=ko`, { waitUntil: 'networkidle' });
  const dialog = page.getByRole('dialog');
  await dialog.waitFor();
  await page.waitForTimeout(800);
  const text = (await dialog.innerText()).replace(/\s+/g, ' ');
  // The summary's large chip is the recorded final action (DecisionDetail).
  const verdict = await dialog.locator('[data-verdict][data-size="lg"]').first().getAttribute('data-verdict');
  return { verdict, mark: markIn(text) };
}

for (const [key, role] of [['A3', 'attacker'], ['A3T', 'owner']]) {
  const runId = latest(key);
  if (!runId) {
    report.push({ key, runId: null });
    continue;
  }
  const score = await api(`/api/runs/${runId}/score`);
  const anatomy = await api(`/api/runs/${runId}/steps/1/anatomy`);
  await page.goto(`${base}/try/${role}/result?lng=ko`, { waitUntil: 'networkidle' });
  await page.locator('main table tbody tr').first().waitFor();
  const contexaRow = (await page.locator('main table tbody tr[data-contexa]').innerText()).replace(/\s+/g, ' ');
  const rows = await page.locator('main table tbody tr').evaluateAll((items) =>
    items.map((row) => ({
      name: (row.querySelector('th')?.textContent ?? '').replace('*', '').trim(),
      cells: [...row.querySelectorAll('td')].map((cell) => cell.innerText.replace(/\s+/g, ' ').trim()),
    })),
  );
  // The result table of try 2 puts try 1 and try 2 side by side; its last column is this run.
  const lastCell = (row) => row.cells[role === 'owner' ? 1 : 0] ?? '';
  const result = {
    contexaWords: wordsIn(role === 'owner' ? (rows.find((row) => row.name === 'Contexa') ? lastCell(rows.find((row) => row.name === 'Contexa')) : '') : contexaRow),
    contexaMark: markIn(role === 'owner' ? lastCell(rows.find((row) => row.name === 'Contexa') ?? { cells: [] }) : contexaRow),
    rows,
  };
  const detail = await detailSummary(runId);
  await page.goto(`${base}/try/summary/recap?lng=ko`, { waitUntil: 'networkidle' });
  await page.locator('main h1').first().waitFor();
  await page.waitForTimeout(800);
  const recapText = (await page.locator('main').innerText()).replace(/\s+/g, ' ');
  report.push({
    key,
    runId,
    api: {
      finalAction: anatomy?.interpretation?.recorded?.finalAction ?? null,
      contexaResult: score?.business?.D?.result ?? null,
      contexaRight: score?.correct?.D ?? null,
      correct: score?.correct ?? null,
      business: Object.fromEntries(Object.entries(score?.business ?? {}).map(([c, b]) => [c, b.result])),
      exposed: Object.fromEntries(Object.entries(score?.business ?? {}).map(([c, b]) => [c, b.exposedItems])),
    },
    result,
    detail,
    recapHasRun: recapText.length > 0,
    recapWords: wordsIn(recapText),
  });
}

// One measured run of the benchmark: the case window's run chip opens the same decision details.
const benchmark = await api('/api/benchmark');
const measuredRun = benchmark.cases.find((row) => row.key === 'A3')?.runIds[0] ?? null;
if (measuredRun) {
  const score = await api(`/api/runs/${measuredRun}/score`);
  const anatomy = await api(`/api/runs/${measuredRun}/steps/1/anatomy`);
  await page.goto(`${base}/benchmark/cases?modal=case&case=A3&lng=ko`, { waitUntil: 'networkidle' });
  const window = page.getByRole('dialog');
  await window.waitFor();
  await page.waitForTimeout(800);
  const windowText = (await window.innerText()).replace(/\s+/g, ' ');
  const detail = await detailSummary(measuredRun);
  report.push({
    key: 'A3 measured',
    runId: measuredRun,
    api: { finalAction: anatomy?.interpretation?.recorded?.finalAction ?? null, contexaRight: score?.correct?.D ?? null },
    caseWindowNamesRun: windowText.includes(measuredRun),
    detail,
  });
}
writeFileSync(join(out, 'same-run.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report.map(({ key, runId, api: a, result, detail }) => ({ key, runId, final: a?.finalAction, words: result?.contexaWords, detail: detail?.verdict, mark: [result?.contexaMark, detail?.mark, a?.contexaRight] }))));
await browser.close();
