// docs/agent Agent중심-화면 AC-6 real-server check (G-12 (1), AC-6 (3)): eight visitors start the open agent case (T5) at the
// same moment on the running portal. The portal admits as many as its cap of agent runs at once (SHOWCASE_LIVE_AGENT_CONCURRENT,
// default 5) and refuses the rest at once with 409 AGENT_BUSY, taking no points from them; the operator status never shows
// more agent runs going than the cap. Each visitor is its own cookie jar. The admitted runs are cancelled by their visitors
// at the end so no slot stays held. The caller compares the points and the ledger with the database.
// Cost: up to the cap's worth of short agent runs (the agent on luna and control D's decisions for their requests).
// Usage (web folder): node e2e/s3-ac6-concurrency-check.mjs <outDir> [--base http://127.0.0.1:19180] [--ops http://127.0.0.1:19190]
import fs from 'node:fs';
import path from 'node:path';
import { request } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s3-ac6-concurrency-check.mjs <outDir> [--base <url>] [--ops <url>]');
  process.exit(2);
}
const option = (name, fallback) => {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : fallback;
};
const base = option('--base', 'http://127.0.0.1:19180');
const ops = option('--ops', 'http://127.0.0.1:19190');
const VISITORS = 8;
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [], answers: [], mostActive: 0 };
function check(name, ok, detail = '') {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

const opsContext = await request.newContext({ baseURL: ops });
const status = async () => (await opsContext.get('/ops/live/status')).json();
const before = await status();
const cap = before.agent.agentConcurrent;
check('the operator status names the cap and no agent run going', before.agent.agentRunsActive === 0, JSON.stringify(before.agent));

const visitors = [];
for (let i = 0; i < VISITORS; i += 1) {
  const context = await request.newContext({ baseURL: base, extraHTTPHeaders: { Accept: 'application/json' } });
  await context.get('/api/visitor');
  const cookies = (await context.storageState()).cookies;
  const xsrf = cookies.find((cookie) => cookie.name === 'XSRF-TOKEN')?.value ?? '';
  visitors.push({ context, xsrf, id: i + 1 });
}
const configs = await Promise.all(visitors.map(async (v) => (await v.context.get('/api/live/config')).json()));
const pointsBefore = configs.map((config) => config.remainingToday);
check('every visitor starts with its points and 2 agent runs', configs.every((config) => config.remainingAgentToday === 2));

// the same moment: every start is sent before any answer is awaited
const answers = await Promise.all(visitors.map(async (v) => {
  const response = await v.context.post('/api/live/runs', {
    data: { scenario: 'T5', turnstileToken: null },
    headers: { 'X-XSRF-TOKEN': v.xsrf, 'Content-Type': 'application/json' },
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { visitor: v.id, status: response.status(), reason: body?.reason ?? null };
}));
report.answers = answers;
const admitted = answers.filter((answer) => answer.status === 202);
const refused = answers.filter((answer) => answer.status === 409);
check(`${cap} of the ${VISITORS} starts are admitted`, admitted.length === cap, `${admitted.length} admitted, statuses ${answers.map((a) => a.status).join(',')}`);
check('the rest are refused at once with 409 and the reason AGENT_BUSY', refused.length === VISITORS - cap
  && refused.every((answer) => answer.reason === 'AGENT_BUSY'), JSON.stringify(refused));

// while they run: never more than the cap, and the refused visitors paid nothing
const started = Date.now();
while (Date.now() - started < 20_000) {
  const now = await status();
  report.mostActive = Math.max(report.mostActive, now.agent.agentRunsActive);
  await new Promise((resolve) => setTimeout(resolve, 1000));
}
check('the operator status never showed more agent runs than the cap', report.mostActive <= cap && report.mostActive >= 1,
  `most ${report.mostActive}, cap ${cap}`);
const after = await Promise.all(visitors.map(async (v) => (await v.context.get('/api/live/config')).json()));
for (const answer of refused) {
  const index = answer.visitor - 1;
  check(`refused visitor ${answer.visitor} paid no points and used no agent run`, after[index].remainingToday === pointsBefore[index]
    && after[index].remainingAgentToday === 2);
}
for (const answer of admitted) {
  const index = answer.visitor - 1;
  check(`admitted visitor ${answer.visitor} paid an agent run's 3 points`, pointsBefore[index] - after[index].remainingToday === 3,
    `${pointsBefore[index]} -> ${after[index].remainingToday}`);
}
check('the config shows the agent runs going and the cap', after[0].agentConcurrent === cap && typeof after[0].agentRunsActive === 'number');

// end the admitted runs so no slot stays held: each visitor, as the delegating employee, rejects the confirmation its agent
// waits for (a run keeps its place until it is answered or its ten minutes run out)
for (const answer of admitted) {
  const v = visitors[answer.visitor - 1];
  const view = await (await v.context.get('/api/live/runs/current')).json().catch(() => null);
  if (view?.status === 'CONFIRMING') {
    await v.context.post('/api/live/runs/current/agent-confirmation', {
      data: { approve: false }, headers: { 'X-XSRF-TOKEN': v.xsrf, 'Content-Type': 'application/json' },
    });
  }
}
const waitedFrom = Date.now();
let active = (await status()).agent.agentRunsActive;
while (active > 0 && Date.now() - waitedFrom < 240_000) {
  await new Promise((resolve) => setTimeout(resolve, 3000));
  active = (await status()).agent.agentRunsActive;
}
check('once the runs end, no agent slot stays held', active === 0, `active ${active}`);
const final = await status();
report.final = final.agent;
for (const v of visitors) {
  await v.context.dispose();
}
await opsContext.dispose();
fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
console.log(report.failures.length === 0 ? 'ALL PASS' : `FAILED: ${report.failures.join('; ')}`);
process.exit(report.failures.length === 0 ? 0 : 1);
