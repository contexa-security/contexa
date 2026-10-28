// docs/agent Agent중심-화면 S1 real-server check (G-5): one visitor runs the open agent case (T5) live in a real browser
// on the running portal, from 6-1 to 6-4, and the script records what the portal counted before and after (the points,
// the agent runs left, the run's stop reason) with screenshots of each agent screen. The ledger rows of the run and the
// allotment are compared against the database by the caller (see the S1 record).
// Cost: one agent run (the agent on the production model, control D's decisions: Layer 1 luna; Layer 2 only if the engine
// escalates by itself). Run it once per check.
// Usage (web folder): node e2e/s1-agent-live-check.mjs <outDir> [--base http://127.0.0.1:19180] [--approve]
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s1-agent-live-check.mjs <outDir> [--base <url>] [--approve]');
  process.exit(2);
}
const baseAt = args.indexOf('--base');
const base = baseAt >= 0 ? args[baseAt + 1] : 'http://127.0.0.1:19180';
const approve = args.includes('--approve');
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [], before: null, after: null, run: null };
function check(name, ok, detail = '') {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

const browser = await chromium.launch();
try {
  const context = await browser.newContext({ locale: 'ko-KR', viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  const json = async (url) => (await page.request.get(base + url)).json();
  const shot = (name) => page.screenshot({ path: path.join(out, `${name}.png`), fullPage: true });

  await page.goto(`${base}/?lng=ko`, { waitUntil: 'networkidle' });
  report.before = await json('/api/live/config');
  check('the config lists the open agent case as an AGENT option', report.before.agentCases?.[0]?.subject === 'AGENT',
    JSON.stringify(report.before.agentCases));
  check('the config carries the agent run points and the agent runs left', report.before.agentRunPoints === 3
    && report.before.dailyAgentRuns === 2 && typeof report.before.remainingAgentToday === 'number',
  `points ${report.before.agentRunPoints}, daily ${report.before.dailyAgentRuns}, left ${report.before.remainingAgentToday}`);
  check('every scenario option names its subject', report.before.scenarios.every((s) => s.subject === 'PERSON'));

  // 1-1: the two columns, the agent's first
  await page.goto(`${base}/?lng=ko`, { waitUntil: 'networkidle' });
  const tracks = await page.locator('[data-track]').evaluateAll((nodes) => nodes.map((n) => n.getAttribute('data-track')));
  check('1-1 shows the agent column first and the person column second', tracks.join() === 'agent,person', tracks.join());
  await shot('1-1');

  // 6-1: the chain, the chip, the prediction and the send
  await page.goto(`${base}/agent/request?lng=ko`, { waitUntil: 'networkidle' });
  await page.getByLabel('보내는 쪽: 위임 에이전트').first().waitFor({ timeout: 15000 });
  check('6-1 names the sender as a delegated agent', true);
  check('6-1 shows the delegation chain', (await page.getByRole('list', { name: '위임 사슬' }).count()) === 1);
  await shot('6-1');
  await page.locator('label', { hasText: '멈춘다' }).first().click();
  await page.getByRole('button', { name: '에이전트에게 맡기기' }).click();
  await page.waitForURL(/\/agent\/console/, { timeout: 30000 });
  check('the send opens 6-2', true);

  // the run: until it is stored (finished, or waiting for the delegating person)
  const started = Date.now();
  let view = null;
  while (Date.now() - started < 9 * 60 * 1000) {
    const response = await page.request.get(`${base}/api/live/runs/current`);
    view = response.ok() ? await response.json() : null;
    if (view && ['COMPLETED', 'CONFIRMING', 'FAILED', 'CANCELLED', 'ABANDONED'].includes(view.status)) {
      break;
    }
    await page.waitForTimeout(5000);
  }
  report.run = view ? { runId: view.runId, status: view.status, liveRunId: view.liveRunId } : null;
  check('the live run reached a stored state', !!view && ['COMPLETED', 'CONFIRMING'].includes(view.status),
    JSON.stringify(report.run));
  await page.goto(`${base}/agent/console?lng=ko`, { waitUntil: 'networkidle' });
  await shot('6-2');
  const measure = page.getByRole('complementary', { name: '숫자의 근거' });
  check('6-2 says whose run it shows and the limit of one run', (await measure.count()) === 1
    && (await measure.innerText()).includes('방문자 본인이 보낸 실행 1회'));
  await page.goto(`${base}/agent/reason?lng=ko`, { waitUntil: 'networkidle' });
  await shot('6-3');
  check('6-3 sets the delegation and the request side by side', (await page.getByRole('region', {
    name: '맡긴 일과 실제 요청을 나란히',
  }).count()) === 1);
  await page.goto(`${base}/agent/confirm?lng=ko`, { waitUntil: 'networkidle' });
  await shot('6-4');
  if (approve && view?.status === 'CONFIRMING') {
    await page.getByRole('button', { name: '승인' }).click();
    await page.waitForTimeout(8000);
    await shot('6-4-approved');
  }

  await page.waitForTimeout(3000);
  report.after = await json('/api/live/config');
  const run = view?.runId ? await json(`/api/runs/${view.runId}/agent`) : null;
  report.agentRun = run
    ? { stopReason: run.stopReason, steps: run.steps.length, cost: run.cost, sender: run.sender }
    : null;
  check('the visitor points fell by an agent run (3 points)',
    report.before.remainingToday - report.after.remainingToday === 3,
    `${report.before.remainingToday} -> ${report.after.remainingToday}`);
  check('the agent runs left fell by one',
    report.before.remainingAgentToday - report.after.remainingAgentToday === 1,
    `${report.before.remainingAgentToday} -> ${report.after.remainingAgentToday}`);
  check('no script error on the screens', errors.length === 0, errors.slice(0, 2).join(' | '));
} finally {
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(report.failures.length === 0 ? 'ALL PASS' : `FAILED: ${report.failures.join('; ')}`);
process.exit(report.failures.length === 0 ? 0 : 1);
