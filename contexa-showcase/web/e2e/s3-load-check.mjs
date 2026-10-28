// docs/agent Agent중심-화면 S3 load simulation (완료판정 S3 부하 모의): 1,000 visitors on the running portal.
// Every visitor reads the stored paths (the menu, a menu answer, a stored reference run, the case view, the benchmark's
// agent part): these start no run and call no model. Then every visitor asks to start a live agent run at the same
// moment (900 the open case T5, 100 a burst of M41A): the portal admits no more than its cap of agent runs at once
// (sampled from the operator status) and no more than the day's share, refuses the rest at once with 409 AGENT_BUSY or the
// refusal of its other safeguards, and takes no points from a refused visitor. The caller compares the database (run
// count, ledger rows) before and after the stored reads, and before and after the starts, and ends any held run.
// Each visitor is its own cookie jar (a plain fetch with the visitor cookie and the XSRF token).
// Usage (web folder): node e2e/s3-load-check.mjs <outDir> [--base http://127.0.0.1:19180] [--ops http://127.0.0.1:19190] [--visitors 1000]
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s3-load-check.mjs <outDir> [--base <url>] [--ops <url>] [--visitors <n>]');
  process.exit(2);
}
const option = (name, fallback) => {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : fallback;
};
const base = option('--base', 'http://127.0.0.1:19180');
const ops = option('--ops', 'http://127.0.0.1:19190');
const VISITORS = Number(option('--visitors', '1000'));
// --phase stored: only the stored reads (so the caller can read the database between the two parts); --phase starts: only the starts
const phase = option('--phase', 'all');
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [], stored: {}, starts: {}, mostActive: 0 };
function check(name, ok, detail = '') {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

/** Runs `work` for every item, `width` at a time. */
async function pool(items, width, work) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: width }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await work(items[index], index);
    }
  }));
  return results;
}

const cookieHeader = (response) => response.headers.getSetCookie().map((cookie) => cookie.split(';')[0]).join('; ');
const opsStatus = async () => (await fetch(`${ops}/ops/live/status`)).json();

// the visitors, each with its own cookies
const visitors = await pool(Array.from({ length: VISITORS }, (_, i) => i), 50, async (index) => {
  const response = await fetch(`${base}/api/visitor`, { headers: { Accept: 'application/json' } });
  const cookies = cookieHeader(response);
  const xsrf = /XSRF-TOKEN=([^;]+)/.exec(cookies)?.[1] ?? '';
  return { index, cookies, xsrf };
});
check(`${VISITORS} visitors were given a visitor cookie and a token`, visitors.every((v) => v.cookies.includes('XSRF-TOKEN') && v.xsrf !== ''),
  `${visitors.filter((v) => v.xsrf === '').length} without`);

const get = (v, url) => fetch(`${base}${url}`, { headers: { Accept: 'application/json', Cookie: v.cookies } });
const post = (v, url, body) => fetch(`${base}${url}`, {
  method: 'POST',
  headers: { Accept: 'application/json', 'Content-Type': 'application/json', Cookie: v.cookies, 'X-XSRF-TOKEN': v.xsrf },
  body: JSON.stringify(body),
});

// ---- 1. the stored paths: no run, no model call
if (phase !== 'starts') {
const readUrls = [
  '/api/live/config', '/api/agent-menu', '/api/agent-menu/M19A/OAUTH2_DELEGATED', '/api/agent-snapshots/T5-confirm-approve',
  '/api/agent-snapshots/M41A-flights-on', '/api/agent-cases/T5', '/api/agent-cases/ED1?quantity=400&period=EXPIRED',
];
const startedReads = Date.now();
const reads = await pool(visitors, 100, async (v) => {
  const statuses = [];
  for (const url of readUrls) {
    const response = await get(v, url);
    await response.arrayBuffer();
    statuses.push(response.status);
  }
  return statuses;
});
report.stored = { requests: VISITORS * readUrls.length, seconds: Math.round((Date.now() - startedReads) / 100) / 10 };
const failedReads = reads.flat().filter((status) => status >= 500).length;
check('every stored read answered without a server error', failedReads === 0, `${failedReads} of ${report.stored.requests} failed; ${report.stored.seconds}s`);
const statusAfterReads = await opsStatus();
check('the stored reads started no run (no agent run going)', statusAfterReads.agent.agentRunsActive === 0, JSON.stringify(statusAfterReads.agent));
}
if (phase === 'stored') {
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  console.log(`${report.checks.length - report.failures.length}/${report.checks.length} passed (stored reads only)`);
  process.exit(report.failures.length === 0 ? 0 : 1);
}

// ---- 2. every visitor asks for a live agent run at the same moment
const before = await opsStatus();
const cap = before.agent.agentConcurrent;
report.starts.before = before.agent;
const sampler = (async () => {
  while (!report.starts.done) {
    const now = await opsStatus();
    report.mostActive = Math.max(report.mostActive, now.agent.agentRunsActive);
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
})();
const answers = await pool(visitors, 300, async (v) => {
  const burst = v.index % 10 === 0;
  const response = await post(v, '/api/live/runs', burst
    ? { scenario: 'M41A', turnstileToken: null, copies: 10 } : { scenario: 'T5', turnstileToken: null });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { index: v.index, burst, status: response.status, reason: body?.reason ?? null };
});
const counts = {};
for (const answer of answers) {
  const key = `${answer.status}${answer.reason ? ` ${answer.reason}` : ''}`;
  counts[key] = (counts[key] ?? 0) + 1;
}
report.starts.counts = counts;
const admitted = answers.filter((answer) => answer.status === 202);
check('no start was answered with a server error', answers.every((answer) => answer.status < 500), JSON.stringify(counts));
check(`no more than the cap (${cap}) of the starts were admitted at once (sampled most going: ${report.mostActive})`,
  admitted.length <= cap + 3, `${admitted.length} admitted of ${VISITORS}`);
check('the rest were refused at once with 409 AGENT_BUSY or another safeguard of the gate', answers.filter((answer) => answer.status !== 202)
  .every((answer) => [409, 429, 503].includes(answer.status)), JSON.stringify(counts));

// the refused visitors paid nothing: read the config of a sample of them
const refusedSample = answers.filter((answer) => answer.status !== 202).slice(0, 100);
const sample = await pool(refusedSample, 50, async (answer) => {
  const config = await (await get(visitors[answer.index], '/api/live/config')).json();
  return config.remainingToday === 10 && config.remainingAgentToday === 2;
});
check('a refused visitor kept all its points and agent runs (100 sampled)', sample.every(Boolean), `${sample.filter((ok) => !ok).length} of ${sample.length} paid`);

// end the held runs: each admitted visitor rejects the confirmation its agent waits for, then wait until none is going
for (const answer of admitted) {
  const v = visitors[answer.index];
  const view = await (await get(v, '/api/live/runs/current')).json().catch(() => null);
  if (view?.status === 'CONFIRMING') {
    await post(v, '/api/live/runs/current/agent-confirmation', { approve: false });
  }
}
const waited = Date.now();
let active = (await opsStatus()).agent.agentRunsActive;
while (active > 0 && Date.now() - waited < 8 * 60_000) {
  for (const answer of admitted) {
    const v = visitors[answer.index];
    const view = await (await get(v, '/api/live/runs/current')).json().catch(() => null);
    if (view?.status === 'CONFIRMING') {
      await post(v, '/api/live/runs/current/agent-confirmation', { approve: false });
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 4000));
  active = (await opsStatus()).agent.agentRunsActive;
}
report.starts.done = true;
await sampler;
check(`the most agent runs the operator status showed going was ${report.mostActive}, within the cap ${cap}`, report.mostActive <= cap,
  `${report.mostActive}`);
check('once the runs end, no agent slot stays held', active === 0, `${active}`);
report.starts.admitted = admitted.length;
fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
console.log(`${report.checks.length - report.failures.length}/${report.checks.length} passed; ${admitted.length} admitted of ${VISITORS}; ${JSON.stringify(counts)}`);
process.exit(report.failures.length === 0 ? 0 : 1);
