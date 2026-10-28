// docs/agent Agent중심-화면 AS-13 / AC-7b real-server check (G-12 (3), AS-13 (1)(2)(3)): a visitor's live burst on the running
// portal. (1) every start the portal must refuse (a number above ten, zero, negative, not a number, no number for the burst
// case, a number for any other case, a delegation on the burst case, a measurement case that is not open) answers 400 and
// takes no points, no agent run and starts no run; (2) a burst of ten really runs, ends, costs 5 points and 1 of the 2 daily
// agent runs; (3) the counts the portal makes of the run (the run view's `burst`) agree with the counts made again here from
// the run's own steps; (4) the structure the stored measurement shows holds: the analyses with a verdict of their own are
// a single digit, nothing the engine refused as busy (no 429), nothing delivered after the first stop. D's concurrent
// analyses are read from D's own log by the caller. The saved JSON is the run exactly as the portal served it.
// Cost: one live burst (the script requests of the case; the engine's analyses of at most a few of them).
// Usage (web folder): node e2e/s3-burst-check.mjs <outDir> [--base http://127.0.0.1:19180] [--copies 10]
import fs from 'node:fs';
import path from 'node:path';
import { request } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s3-burst-check.mjs <outDir> [--base <url>] [--copies <n>]');
  process.exit(2);
}
const option = (name, fallback) => {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : fallback;
};
const base = option('--base', 'http://127.0.0.1:19180');
const copies = Number(option('--copies', '10'));
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [], refusals: [], run: null };
function check(name, ok, detail = '') {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

const context = await request.newContext({ baseURL: base, extraHTTPHeaders: { Accept: 'application/json' } });
await context.get('/api/visitor');
const xsrf = (await context.storageState()).cookies.find((cookie) => cookie.name === 'XSRF-TOKEN')?.value ?? '';
const post = async (data) => {
  const response = await context.post('/api/live/runs', {
    data, headers: { 'X-XSRF-TOKEN': xsrf, 'Content-Type': 'application/json' },
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status(), body };
};
const config = async () => (await context.get('/api/live/config')).json();
const current = async () => {
  const response = await context.get('/api/live/runs/current');
  return response.status() === 200 ? response.json().catch(() => null) : null;
};

// the portal offers the burst, with the numbers the screen reads
const before = await config();
check('the config offers the burst case with the most (10), the measured size (60) and the points (5)',
  before.burst?.case === 'M41A' && before.burst.most === 10 && before.burst.measured === 60 && before.burst.points === 5,
  JSON.stringify(before.burst));
check('the burst case is no entry of the open agent cases', !(before.agentCases ?? []).some((found) => found.key === 'M41A'),
  (before.agentCases ?? []).map((found) => found.key).join(','));

// (1) what the portal must refuse
const refused = [
  ['11 requests', { scenario: 'M41A', copies: 11, turnstileToken: null }],
  ['60 requests (the stored measurement)', { scenario: 'M41A', copies: 60, turnstileToken: null }],
  ['1000 requests', { scenario: 'M41A', copies: 1000, turnstileToken: null }],
  ['0 requests', { scenario: 'M41A', copies: 0, turnstileToken: null }],
  ['-1 requests', { scenario: 'M41A', copies: -1, turnstileToken: null }],
  ['not a number', { scenario: 'M41A', copies: 'many', turnstileToken: null }],
  ['no number for the burst case', { scenario: 'M41A', turnstileToken: null }],
  ['a number for another open case', { scenario: 'T5', copies: 5, turnstileToken: null }],
  ['a delegation choice on the burst case', { scenario: 'M41A', copies: 5, delegation: { quantity: 400 }, turnstileToken: null }],
  ['a measurement case that is not open (M41T)', { scenario: 'M41T', copies: 5, turnstileToken: null }],
  ['a measurement case that is not open (M41X)', { scenario: 'M41X', turnstileToken: null }],
];
for (const [name, data] of refused) {
  const answer = await post(data);
  report.refusals.push({ name, status: answer.status });
  check(`refused with 400: ${name}`, answer.status === 400, `status ${answer.status}`);
}
const afterRefusals = await config();
check('the refusals took no points and no agent run', afterRefusals.remainingToday === before.remainingToday
  && afterRefusals.remainingAgentToday === before.remainingAgentToday,
`${before.remainingToday}/${before.remainingAgentToday} -> ${afterRefusals.remainingToday}/${afterRefusals.remainingAgentToday}`);
check('the refusals started no run', (await current()) === null);

// (2) a burst of the number really runs
const started = await post({ scenario: 'M41A', turnstileToken: null, copies });
check(`a burst of ${copies} is admitted (202)`, started.status === 202, `status ${started.status} ${JSON.stringify(started.body?.reason ?? '')}`);
if (started.status === 202) {
  const mid = await config();
  check('it costs 5 points and 1 of the daily agent runs while it runs', before.remainingToday - mid.remainingToday === 5
    && before.remainingAgentToday - mid.remainingAgentToday === 1,
  `${before.remainingToday}/${before.remainingAgentToday} -> ${mid.remainingToday}/${mid.remainingAgentToday}`);

  const began = Date.now();
  let view = started.body;
  const seen = new Set();
  while (Date.now() - began < 8 * 60_000) {
    view = (await current()) ?? view;
    seen.add(view.status);
    if (['COMPLETED', 'FAILED', 'EXPIRED'].includes(view.status)) {
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  report.run = { liveRunId: view.liveRunId, status: view.status, runId: view.runId, seconds: Math.round((Date.now() - began) / 1000),
    statuses: [...seen] };
  check('the burst run ends COMPLETED', view.status === 'COMPLETED', JSON.stringify(report.run));
  const end = await config();
  check('a completed burst stays paid: 5 points and 1 agent run', before.remainingToday - end.remainingToday === 5
    && before.remainingAgentToday - end.remainingAgentToday === 1,
  `${before.remainingToday}/${before.remainingAgentToday} -> ${end.remainingToday}/${end.remainingAgentToday}`);

  if (view.runId) {
    const run = await (await context.get(`/api/runs/${view.runId}/agent`)).json();
    fs.writeFileSync(path.join(out, `burst-${copies}.json`), JSON.stringify(run, null, 2));
    const summary = run.burst;
    check('the run view carries the portal\'s counts of the burst', summary && typeof summary.requests === 'number',
      JSON.stringify(summary));
    if (summary) {
      // (3) the same counts, made again here from the run's own steps
      const steps = run.steps;
      const delivered = steps.filter((step) => step.outcomes?.D?.outcome === 'DELIVERED').length;
      const busy = steps.filter((step) => step.outcomes?.D?.rule === 'ZERO_TRUST_ANALYSIS_BUSY').length;
      const verdicts = steps.filter((step) => step.decision?.final_action != null).length;
      const calls = steps.reduce((sum, step) => sum + (step.decision?.model_calls ?? 0), 0);
      const firstStop = run.proof?.controls?.D?.firstStopStep ?? null;
      const afterStop = firstStop === null ? 0
        : steps.filter((step) => step.stepNo > firstStop && step.outcomes?.D?.outcome === 'DELIVERED').length;
      check('the counts agree with a recount from the steps', summary.requests === steps.length && summary.delivered === delivered
        && summary.refused === steps.length - delivered && summary.busy === busy && summary.withVerdict === verdicts
        && summary.modelCalls === calls && summary.firstStopStep === firstStop && summary.deliveredAfterFirstStop === afterStop,
      JSON.stringify({ summary, recount: { requests: steps.length, delivered, busy, verdicts, calls, firstStop, afterStop } }));
      // (4) the structure of the measurement
      check(`at least the ${copies} burst requests were sent`, summary.requests >= copies, `${summary.requests} requests`);
      check('the analyses with a verdict of their own are a single digit', summary.withVerdict <= 9, `${summary.withVerdict}`);
      check('no request was refused as busy (no 429)', summary.busy === 0, `${summary.busy}`);
      check('nothing was delivered after the first stop (no leak)', summary.deliveredAfterFirstStop === 0,
        `${summary.deliveredAfterFirstStop}`);
    }
  }
}

fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
console.log(`${report.checks.length - report.failures.length}/${report.checks.length} passed`);
await context.dispose();
process.exit(report.failures.length === 0 ? 0 : 1);
