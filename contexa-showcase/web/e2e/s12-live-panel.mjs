// S12 C-12 on the real stack: while try 1 runs (one live run), every 250 ms the inside panel's nine cells and the
// engine's analysis events (/api/live/runs/current/analysis) are written down together. A cell may light only once the
// event it stands for is in (insideCells.ts: request with the first event, the three context cells with
// CONTEXT_COLLECTED, the prompt with LAYER1_START, the judgement with DECISION_APPLIED, the decision with the decision
// block), the cells light in the panel's order, and the decision shows no later than the run's end.
// Usage: node e2e/s12-live-panel.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:19180';
const m = JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8'));
mkdirSync(out, { recursive: true });

const CELLS = ['request', 'usual', 'company', 'history', 'prompt', 'judgement', 'decision', 'followUp', 'learning'];
const NEEDS = {
  usual: 'CONTEXT_COLLECTED',
  company: 'CONTEXT_COLLECTED',
  history: 'CONTEXT_COLLECTED',
  prompt: 'LAYER1_START',
};
const lit = (state) => state === 'done' || state === 'decision';

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: 'ko' });
await page.goto(`${base}/try/attacker/predict?lng=ko`, { waitUntil: 'networkidle' });
await page.getByText(m['e1.predict.CHALLENGE'], { exact: true }).first().click();
await page.locator('main [data-main]').click();
await page.waitForURL(/\/try\/attacker\/run/);
const started = Date.now();
const samples = [];
const done = page.getByRole('link', { name: m['e1.next.result'] });
while (Date.now() - started < 300_000) {
  const sample = await page.evaluate(async () => {
    const cells = [...document.querySelectorAll('aside li[data-state]')].map((li) => li.getAttribute('data-state'));
    const analysis = await fetch('/api/live/runs/current/analysis?step=1').then((r) => (r.ok ? r.json() : null));
    const run = await fetch('/api/live/runs/current').then((r) => (r.ok ? r.json() : null));
    return {
      cells,
      events: (analysis?.stages ?? []).map((stage) => stage.type),
      decision: analysis?.decision?.finalAction ?? null,
      status: run?.status ?? null,
    };
  });
  samples.push({ atMs: Date.now() - started, ...sample });
  if ((await done.count()) > 0 && sample.status === 'COMPLETED') break;
  await page.waitForTimeout(250);
}
const first = (predicate) => samples.find(predicate)?.atMs ?? null;
const lights = Object.fromEntries(CELLS.map((cell, index) => [cell, first((s) => lit(s.cells[index]))]));
const problems = [];
for (const sample of samples) {
  CELLS.forEach((cell, index) => {
    if (!lit(sample.cells[index])) return;
    if (NEEDS[cell] && !sample.events.includes(NEEDS[cell])) {
      problems.push(`${cell} lit at ${sample.atMs} ms before ${NEEDS[cell]}`);
    }
    if (cell === 'judgement' && !sample.events.some((type) => type === 'DECISION_APPLIED' || type === 'ANALYSIS_ERROR')) {
      problems.push(`judgement lit at ${sample.atMs} ms before the analysis closed`);
    }
    if (cell === 'decision' && sample.decision === null) {
      problems.push(`decision lit at ${sample.atMs} ms before the decision block`);
    }
  });
}
const order = CELLS.slice(0, 7).map((cell) => lights[cell]);
for (let index = 1; index < order.length; index += 1) {
  if (order[index] !== null && order[index - 1] !== null && order[index] < order[index - 1]) {
    problems.push(`${CELLS[index]} lit before ${CELLS[index - 1]}`);
  }
}
const completedAt = first((s) => s.status === 'COMPLETED');
if (lights.decision === null) problems.push('the decision never showed');
else if (completedAt !== null && lights.decision > completedAt) problems.push('the decision showed after the run ended');
const eventsAt = Object.fromEntries(
  [...new Set(samples.flatMap((s) => s.events))].map((type) => [type, first((s) => s.events.includes(type))]),
);
writeFileSync(join(out, 'live-panel.json'), JSON.stringify({ lights, eventsAt, completedAt, problems, samples }, null, 2));
console.log(JSON.stringify({ lights, eventsAt, completedAt, problems: [...new Set(problems)].slice(0, 10) }));
await browser.close();
