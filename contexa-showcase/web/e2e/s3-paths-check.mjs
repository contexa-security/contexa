// docs/agent Agent중심-화면 S3 real-server check of the new live paths AS-12 (the delegation edit) and AS-14 (the five open
// cases), in a real browser per visitor on the running portal (G-12, AS-12 (1)-(6), AS-14).
// AS-12: (1) every value outside the lists is refused with 400 (a start and the case view) and takes nothing; (2) four runs
// of the editable case ED1 with different choices (inside the delegation, reading only, revoked, inside again) each record
// the delegation they executed (limit, operations, status) and do not bleed into one another or into the case itself;
// (3) a run of the case as it is is answered at its confirmation: approved by one visitor, rejected by another.
// AS-14: each open case (T5, N1, M14A, M22A, M10A) is run once end to end by its own visitor, its result screens
// (6-2, 6-3, 6-5, 6-7) are opened for that case with screenshots, and what control D did is set beside the case's
// classification (reported, not judged: a measured fact).
// Cost: ten short agent runs (the agent on luna, control D's decisions for their requests).
// Usage (web folder): node e2e/s3-paths-check.mjs <outDir> [--base http://127.0.0.1:19180]
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s3-paths-check.mjs <outDir> [--base <url>]');
  process.exit(2);
}
const baseAt = args.indexOf('--base');
const base = baseAt >= 0 ? args[baseAt + 1] : 'http://127.0.0.1:19180';
// --only confirm runs just the confirmation part of AS-12 (the others are skipped)
const onlyAt = args.indexOf('--only');
const only = onlyAt >= 0 ? args[onlyAt + 1] : null;
const part = (name) => only === null || only === name;
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [], runs: {}, cases: {} };
function check(name, ok, detail = '') {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

const browser = await chromium.launch();

/** A new visitor in a browser of its own. */
async function visitor() {
  const context = await browser.newContext({ locale: 'ko-KR', viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  await page.goto(`${base}/?lng=ko`, { waitUntil: 'networkidle' });
  const xsrf = (await context.storageState()).cookies.find((cookie) => cookie.name === 'XSRF-TOKEN')?.value ?? '';
  const headers = { 'X-XSRF-TOKEN': xsrf, 'Content-Type': 'application/json' };
  return {
    context, page, errors,
    get: async (url) => {
      const response = await page.request.get(base + url);
      let body = null;
      try {
        body = await response.json();
      } catch {
        body = null;
      }
      return { status: response.status(), body };
    },
    post: async (url, data) => {
      const response = await page.request.post(base + url, { data, headers });
      let body = null;
      try {
        body = await response.json();
      } catch {
        body = null;
      }
      return { status: response.status(), body };
    },
  };
}

/** Starts a run, answers its confirmation as told (approve true/false, or none), waits for it to end. */
async function drive(v, data, approve = null) {
  const config0 = (await v.get('/api/live/config')).body;
  const started = await v.post('/api/live/runs', data);
  if (started.status !== 202) {
    return { started, config0 };
  }
  const began = Date.now();
  let view = started.body;
  const seen = new Set();
  let answered = false;
  while (Date.now() - began < 9 * 60_000) {
    const now = await v.get('/api/live/runs/current');
    view = now.body ?? view;
    seen.add(view.status);
    if (view.status === 'CONFIRMING' && approve !== null && !answered) {
      answered = true;
      await v.post('/api/live/runs/current/agent-confirmation', { approve });
    }
    if (['COMPLETED', 'FAILED', 'EXPIRED'].includes(view.status)) {
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 4000));
  }
  const config1 = (await v.get('/api/live/config')).body;
  const run = view.runId ? (await v.get(`/api/runs/${view.runId}/agent`)).body : null;
  return { started, view, seen: [...seen], answered, config0, config1, run, seconds: Math.round((Date.now() - began) / 1000) };
}

function outcomeOf(run) {
  if (!run) {
    return null;
  }
  const first = run.proof?.controls?.D?.firstStopStep ?? null;
  return {
    steps: run.steps.length,
    firstStopStep: first,
    stopReason: run.stopReason,
    confirmation: run.confirmation ? { status: run.confirmation.status ?? null, answer: run.confirmation.answer ?? null } : null,
    delegation: run.delegation ? {
      limit: run.delegation.maxItemsPerRequest ?? null,
      status: run.delegation.status,
      operations: run.delegation.operations,
    } : null,
    items: run.proof?.controls?.D?.items ?? null,
  };
}

try {
  // ---- AS-12 (1): what the portal refuses
  const probe = await visitor();
  if (part('refusals')) {
  const before = (await probe.get('/api/live/config')).body;
  check('the config names the editable case ED1 and its lists', before.delegationEdit?.case === 'ED1'
    && JSON.stringify(before.delegationEdit.quantities) === '[40,100,400]', JSON.stringify(before.delegationEdit));
  const bad = [
    ['quantity 401', { quantity: 401 }], ['quantity -1', { quantity: -1 }], ['quantity "many"', { quantity: 'many' }],
    ['period FOREVER', { period: 'FOREVER' }], ['operations ALL', { operations: 'ALL' }],
  ];
  for (const [name, delegation] of bad) {
    const answer = await probe.post('/api/live/runs', { scenario: 'ED1', turnstileToken: null, delegation });
    check(`a start with ${name} is refused with 400`, answer.status === 400, `status ${answer.status}`);
  }
  const onOther = await probe.post('/api/live/runs', { scenario: 'T5', turnstileToken: null, delegation: { quantity: 400 } });
  check('a delegation choice on another case is refused with 400', onOther.status === 400, `status ${onOther.status}`);
  const viewBad = await probe.get('/api/agent-cases/ED1?quantity=401');
  const viewBad2 = await probe.get('/api/agent-cases/ED1?period=FOREVER');
  const viewOther = await probe.get('/api/agent-cases/T5?quantity=400');
  check('the case view refuses a value outside the lists and a choice on another case (400)', viewBad.status === 400
    && viewBad2.status === 400 && viewOther.status === 400, `${viewBad.status}/${viewBad2.status}/${viewOther.status}`);
  const after = (await probe.get('/api/live/config')).body;
  check('the refusals took no points and no agent run', after.remainingToday === before.remainingToday
    && after.remainingAgentToday === before.remainingAgentToday);
  check('the case view shows a choice as the delegation the run will execute',
    (await probe.get('/api/agent-cases/ED1?quantity=400&period=EXPIRED')).body?.delegation?.maxItemsPerRequest === 400);
  }

  // ---- AS-12 (2): four runs with different choices, then the case itself
  if (part('choices')) {
  const choices = {
    inside: { quantity: 400, period: 'VALID', operations: 'READ_EXPORT' },
    readOnly: { quantity: null, period: null, operations: 'READ_ONLY' },
    revoked: { quantity: null, period: 'REVOKED', operations: null },
    insideAgain: { quantity: 400, period: 'VALID', operations: 'READ_EXPORT' },
  };
  for (const [name, delegation] of Object.entries(choices)) {
    const v = await visitor();
    const result = await drive(v, { scenario: 'ED1', turnstileToken: null, delegation }, true);
    const outcome = outcomeOf(result.run);
    report.runs[`ED1-${name}`] = { status: result.view?.status, outcome, statuses: result.seen, seconds: result.seconds };
    check(`ED1 ${name}: the run ends COMPLETED`, result.view?.status === 'COMPLETED', JSON.stringify(report.runs[`ED1-${name}`]));
    check(`ED1 ${name}: the agent run costs 3 points and 1 agent run`, result.config0.remainingToday - result.config1.remainingToday === 3
      && result.config0.remainingAgentToday - result.config1.remainingAgentToday === 1,
    `${result.config0.remainingToday}/${result.config0.remainingAgentToday} -> ${result.config1.remainingToday}/${result.config1.remainingAgentToday}`);
    check(`ED1 ${name}: the run records the delegation it executed`, outcome?.delegation !== null
      && outcome.delegation.limit === (delegation.quantity ?? 40)
      && outcome.delegation.status === (delegation.period === 'REVOKED' ? 'REVOKED' : 'ACTIVE')
      && outcome.delegation.operations.includes('EXPORT') === (delegation.operations !== 'READ_ONLY'),
    JSON.stringify(outcome?.delegation));
    check(`ED1 ${name}: no script error on the visitor's pages`, v.errors.length === 0, v.errors.slice(0, 2).join(' | '));
    await v.context.close();
  }
  const a = report.runs['ED1-inside'].outcome;
  const b = report.runs['ED1-readOnly'].outcome;
  const c = report.runs['ED1-revoked'].outcome;
  const d = report.runs['ED1-insideAgain'].outcome;
  check('the same choice twice, with others between, gives the same outcome at D', a && d && a.firstStopStep === d.firstStopStep
    && a.items === d.items, JSON.stringify({ a, d }));
  check('reading only stops what the full delegation lets through (the export is outside it)', b && a
    && (b.firstStopStep !== null) && (a.firstStopStep === null || b.firstStopStep <= a.firstStopStep), JSON.stringify({ a, b }));
  // the engine's gate refuses every request of the agent under a revoked delegation (DELEGATION_REVOKED): the work stops at
  // its first request and exports nothing (S3 finding: a revoked delegation of 3 hours used to change nothing)
  check('a revoked delegation stops the work at its first request and exports nothing', c && c.firstStopStep === 1
    && c.items === 0, JSON.stringify(c));
  const own = await probe.get('/api/agent-cases/ED1');
  check('the case itself is untouched by all of it (limit 40, active, export allowed)', own.body?.delegation?.maxItemsPerRequest === 40
    && own.body.delegation.status === 'ACTIVE' && own.body.delegation.operations.includes('EXPORT'), JSON.stringify(own.body?.delegation));
  }
  await probe.context.close();

  // ---- AS-12 (3): a delegation that ended (as in T5), answered at its confirmation: approved by one visitor, rejected by another
  if (part('confirm')) {
  for (const approve of [true, false]) {
    const v = await visitor();
    const result = await drive(v, { scenario: 'ED1', turnstileToken: null, delegation: { quantity: 400, period: 'EXPIRED', operations: 'READ_EXPORT' } }, approve);
    const outcome = outcomeOf(result.run);
    const name = `ED1-expired-${approve ? 'approve' : 'reject'}`;
    report.runs[name] = { status: result.view?.status, outcome, statuses: result.seen, answered: result.answered };
    check(`${name}: the run ends COMPLETED`, result.view?.status === 'COMPLETED', JSON.stringify(report.runs[name]));
    check(`${name}: control D asked the delegating person to confirm and the visitor's answer was taken`,
      result.seen.includes('CONFIRMING') && result.answered, JSON.stringify(report.runs[name]));
    const run = result.run;
    const answer = run?.confirmation?.status ?? run?.confirmation?.answer ?? JSON.stringify(run?.confirmation);
    check(`${name}: the stored run holds the answer (${approve ? 'approved' : 'rejected'})`, JSON.stringify(run?.confirmation ?? '')
      .toUpperCase().includes(approve ? 'APPROV' : 'REJECT') , String(answer));
    await v.context.close();
  }
  }

  // ---- AS-14: the five open cases, each by its own visitor, end to end
  if (part('cases')) {
  const SCREENS = [['console', '6-2'], ['reason', '6-3'], ['end', '6-5'], ['result', '6-7']];
  for (const key of ['T5', 'N1', 'M14A', 'M22A', 'M10A']) {
    const v = await visitor();
    const caseView = (await v.get(`/api/agent-cases/${key}`)).body;
    const result = await drive(v, { scenario: key, turnstileToken: null }, true);
    const outcome = outcomeOf(result.run);
    report.cases[key] = { classification: caseView?.classification, status: result.view?.status, outcome, statuses: result.seen,
      seconds: result.seconds };
    check(`${key}: the visitor's run ends COMPLETED`, result.view?.status === 'COMPLETED', JSON.stringify(report.cases[key]));
    check(`${key}: it costs an agent run's 3 points and 1 agent run`, result.config0.remainingToday - result.config1.remainingToday === 3
      && result.config0.remainingAgentToday - result.config1.remainingAgentToday === 1);
    for (const [screen, number] of SCREENS) {
      await v.page.goto(`${base}/agent/${screen}?case=${key}&lng=ko`, { waitUntil: 'networkidle' });
      const heading = await v.page.locator('h1').first().innerText().catch(() => '');
      check(`${key}: ${number} opens for the case with a heading and no state screen of an error`, heading.length > 0
        && (await v.page.getByText('준비되지 않았습니다').count()) === 0, heading);
      await v.page.screenshot({ path: path.join(out, `${key}-${number}.png`), fullPage: true });
    }
    check(`${key}: no script error on the screens`, v.errors.length === 0, v.errors.slice(0, 2).join(' | '));
    await v.context.close();
  }
  }
} finally {
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(`${report.checks.length - report.failures.length}/${report.checks.length} passed`);
console.log(report.failures.length === 0 ? 'ALL PASS' : `FAILED: ${report.failures.join('; ')}`);
process.exit(report.failures.length === 0 ? 0 : 1);
