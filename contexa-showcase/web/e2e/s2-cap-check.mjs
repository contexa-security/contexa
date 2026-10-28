// docs/agent Agent중심-화면 S2 real-server check, the S1 leftovers (AC-3, AC-2): visitors send agent cases live until the
// portal says no.
// Phase A (API): a visitor starts a case that works in several rounds (N1, open for this check with
//   SHOWCASE_LIVE_AGENT_TASKS=T5,N1) under a low input-token cap (SHOWCASE_AGENT_CAP_INPUT=500): the cap is checked at the
//   tools of a round with the tokens of the rounds before it, so a run of one round (T5) never meets it and a run of
//   several does. Each run must end with stopReason CAP_INPUT_TOKENS and a proof that says it did not complete; the third
//   start of the day is refused with 429.
// Phase B (browser): a visitor sends T5 twice through 6-1 and the third send shows the screen "오늘 직접 보낼 수 있는 횟수를
//   모두 썼습니다." with the way to a stored run.
// Cost: a few short agent runs (luna) and control D's decisions for the requests they send.
// Usage (web folder): node e2e/s2-cap-check.mjs <outDir> [--base http://127.0.0.1:19180] [--case N1]
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s2-cap-check.mjs <outDir> [--base <url>] [--case <key>]');
  process.exit(2);
}
const option = (name, fallback) => {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : fallback;
};
const base = option('--base', 'http://127.0.0.1:19180');
const caseKey = option('--case', 'N1');
// --only A runs the cap phase alone, --only B the screens of the daily limit alone (a phase may be repeated without the other)
const only = option('--only', '');
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [], runs: [], startStatuses: [] };
function check(name, ok, detail = '') {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

const TERMINAL = ['COMPLETED', 'CONFIRMING', 'FAILED', 'CANCELLED', 'ABANDONED'];
const browser = await chromium.launch();
const errors = [];

/** A visitor with its own cookies: the page (for screens) and a JSON helper that carries the CSRF token. */
async function visitor() {
  const context = await browser.newContext({ locale: 'ko-KR', viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  page.on('pageerror', (error) => errors.push(String(error)));
  await page.goto(`${base}/?lng=ko`, { waitUntil: 'networkidle' });
  const json = async (url) => (await page.request.get(base + url)).json();
  const post = async (url, data) => {
    const cookies = await context.cookies();
    const xsrf = cookies.find((cookie) => cookie.name === 'XSRF-TOKEN')?.value ?? '';
    const response = await page.request.post(base + url, { data, headers: { 'X-XSRF-TOKEN': xsrf } });
    let body = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    return { status: response.status(), body };
  };
  return { context, page, json, post };
}

async function waitStored(v) {
  const started = Date.now();
  let view = null;
  while (Date.now() - started < 6 * 60 * 1000) {
    const response = await v.page.request.get(`${base}/api/live/runs/current`);
    view = response.ok() ? await response.json() : null;
    if (view && TERMINAL.includes(view.status)) {
      break;
    }
    await v.page.waitForTimeout(3000);
  }
  return view;
}

try {
  // ---- phase A: the input-token cap, by API
  if (only !== 'B') {
  const a = await visitor();
  const config = await a.json('/api/live/config');
  check(`the config opens ${caseKey} to visitors`, (config.agentCases ?? []).some((open) => open.key === caseKey),
    JSON.stringify((config.agentCases ?? []).map((open) => open.key)));
  check('the visitor starts with 2 agent runs left', config.remainingAgentToday === 2, String(config.remainingAgentToday));
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const started = await a.post('/api/live/runs', { scenario: caseKey, turnstileToken: null });
    report.startStatuses.push(started.status);
    check(`A${attempt}: the start is admitted`, started.status === 202, String(started.status));
    const view = await waitStored(a);
    const run = view?.runId ? await a.json(`/api/runs/${view.runId}/agent`) : null;
    report.runs.push({ attempt, runId: view?.runId, status: view?.status, stopReason: run?.stopReason, steps: run?.steps?.length });
    check(`A${attempt}: the run reached a stored state`, !!view && TERMINAL.includes(view.status), JSON.stringify(report.runs.at(-1)));
    check(`A${attempt}: the run was stopped by the input-token cap`, run?.stopReason === 'CAP_INPUT_TOKENS', String(run?.stopReason));
    check(`A${attempt}: the proof says the work did not complete`, run?.proof?.completed === false);
    check(`A${attempt}: the stopped run keeps the requests it sent`, (run?.steps?.length ?? 0) >= 1, String(run?.steps?.length));
  }
  const spent = await a.json('/api/live/config');
  check('two agent runs used the visitor\'s 2 agent runs and 6 points', spent.remainingAgentToday === 0
    && config.remainingToday - spent.remainingToday === 6, `${config.remainingToday} -> ${spent.remainingToday}`);
  const third = await a.post('/api/live/runs', { scenario: caseKey, turnstileToken: null });
  report.startStatuses.push(third.status);
  check('A3: the third start of the day is refused with 429', third.status === 429, `${third.status} ${JSON.stringify(third.body)}`);
  const afterThird = await a.json('/api/live/config');
  check('the refused start changed nothing', afterThird.remainingToday === spent.remainingToday
    && afterThird.remainingAgentToday === 0);
  await a.context.close();
  }

  // ---- phase B: the screens of the daily agent limit (T5 through 6-1)
  if (only !== 'A') {
  const b = await visitor();
  const shot = (name) => b.page.screenshot({ path: path.join(out, `${name}.png`), fullPage: true });
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    await b.page.goto(`${base}/agent/request?lng=ko`, { waitUntil: 'networkidle' });
    await b.page.getByLabel('보내는 쪽: 위임 에이전트').first().waitFor({ timeout: 15000 });
    await b.page.locator('label', { hasText: '멈춘다' }).first().click();
    await b.page.getByRole('button', { name: '에이전트에게 맡기기' }).click();
    await b.page.waitForURL(/\/agent\/console/, { timeout: 30000 });
    const view = await waitStored(b);
    check(`B${attempt}: the T5 run reached a stored state`, !!view && TERMINAL.includes(view.status), view?.status);
    // End the run: the visitor, as the delegating employee, rejects the confirmation the agent waits for (a run keeps its
    // place until it is answered or its ten minutes run out), then wait until the portal holds no run of this visitor any
    // more: a send while the earlier run is still going answers with that run, not with the limit.
    if (view?.status === 'CONFIRMING') {
      await b.post('/api/live/runs/current/agent-confirmation', { approve: false });
    }
    const ended = Date.now();
    let over = false;
    while (!over && Date.now() - ended < 120_000) {
      const response = await b.page.request.get(`${base}/api/live/runs/current`);
      const now = response.ok() ? await response.json() : null;
      over = now === null || ['COMPLETED', 'FAILED', 'CANCELLED', 'ABANDONED', 'EXPIRED'].includes(now.status);
      if (!over) {
        await b.page.waitForTimeout(2000);
      }
    }
    check(`B${attempt}: the run is over before the next send`, over);
  }
  await b.page.goto(`${base}/agent/request?lng=ko`, { waitUntil: 'networkidle' });
  await b.page.getByLabel('보내는 쪽: 위임 에이전트').first().waitFor({ timeout: 15000 });
  await b.page.locator('label', { hasText: '멈춘다' }).first().click();
  const responded = b.page.waitForResponse((response) => response.url() === `${base}/api/live/runs`
    && response.request().method() === 'POST', { timeout: 30000 });
  await b.page.getByRole('button', { name: '에이전트에게 맡기기' }).click();
  const status = (await responded).status();
  await b.page.getByText('오늘 직접 보낼 수 있는 횟수를 모두 썼습니다.').waitFor({ timeout: 30000 });
  await shot('6-1-limit');
  check('B3: the third send of T5 is refused with HTTP 429', status === 429, String(status));
  check('B3: the refusal screen leads to a stored run', (await b.page.getByRole('link', { name: /저장된|기록/ }).count()) >= 1);
  await b.context.close();
  }
  check('no script error on the screens', errors.length === 0, errors.slice(0, 2).join(' | '));
} finally {
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(report.failures.length === 0 ? 'ALL PASS' : `FAILED: ${report.failures.join('; ')}`);
process.exit(report.failures.length === 0 ? 0 : 1);
