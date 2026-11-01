// UX-R1 I-4 real-server check (완료판정기준 I-4): real runs through the new screens served by the portal — the agent
// cases T5 (the delegating person approves) and N1 by one visitor (two agent runs a day), the live burst and one composed
// lab run by a second visitor — and each result compared with the portal's HTTP answers and its database rows. Paid
// runs: record the batch in UX-R1-비용장부.md before and after.
//
//   node ux_real_i4.mjs --base http://127.0.0.1:19180 --out <dir> [--only T5,N1,BURST,LAB]
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const require = createRequire('E:/projects/contexa/contexa-showcase/web/package.json');
const { chromium } = require('playwright');

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index > 0 ? process.argv[index + 1] : fallback;
}
const base = arg('base', 'http://127.0.0.1:19180');
const out = arg('out', '.').replace(/^\/([a-z])\//i, (_, drive) => `${drive.toUpperCase()}:/`);
const only = arg('only', 'T5,N1,BURST,LAB').split(',');
mkdirSync(out, { recursive: true });

/** Rows of the portal database (container contexa-showcase-postgres-1), never secrets. */
function db(sql) {
  const text = execFileSync(
    'docker',
    ['exec', '-i', 'contexa-showcase-postgres-1', 'sh', '-c', 'psql -U "$POSTGRES_USER" -d showcase_portal -At -F "|"'],
    { input: sql, encoding: 'utf8' },
  );
  return text.split('\n').filter(Boolean).map((line) => line.split('|'));
}

const report = { base, startedAt: new Date().toISOString(), runs: [], problems: [] };
const browser = await chromium.launch();

async function visitor() {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR' });
  const page = await context.newPage();
  page.setDefaultTimeout(20000);
  return page;
}

async function json(page, path) {
  const response = await page.request.get(`${base}${path}`);
  return response.ok() ? response.json() : { status: response.status() };
}

async function enabled(page, name) {
  const button = page.getByRole('button', { name, exact: true });
  await button.waitFor();
  await page.waitForFunction(
    (label) => [...document.querySelectorAll('button')].some((b) => b.textContent?.trim() === label && b.getAttribute('aria-disabled') !== 'true' && !b.disabled),
    name,
    { timeout: 30000 },
  );
  return button;
}

async function shots(page, name) {
  await page.screenshot({ path: join(out, `${name}-1440.png`), fullPage: true });
  await page.setViewportSize({ width: 390, height: 900 });
  await page.screenshot({ path: join(out, `${name}-390.png`), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 900 });
}

/** The agent run's record against the database: every step's control D outcome and the confirmation. */
function compareAgent(entry, record) {
  const steps = db(`select step_no, control, outcome, delivered_items from run_arm_result where run_id = '${entry.runId}' and control = 'D' order by step_no;`);
  entry.db = {
    run: db(`select scenario_key, status, live_run from run where run_id = '${entry.runId}';`)[0] ?? null,
    stepsD: steps,
    decisions: db(`select step_no, final_action, model_calls from run_decision where run_id = '${entry.runId}' order by step_no;`),
    confirmation: db(`select step_no, trigger, decision, decide_status, status_after from run_agent_confirmation where run_id = '${entry.runId}';`),
  };
  const httpD = record.steps.map((step) => [String(step.stepNo), step.outcomes.D?.outcome ?? null, String(step.outcomes.D?.deliveredItems ?? '')]);
  const dbD = steps.map(([stepNo, , outcome, items]) => [stepNo, outcome, items]);
  if (JSON.stringify(httpD) !== JSON.stringify(dbD)) {
    report.problems.push(`${entry.key}: HTTP D per step ${JSON.stringify(httpD)} ≠ DB ${JSON.stringify(dbD)}`);
  }
  if (record.confirmation && entry.db.confirmation.length > 0) {
    const [stepNo, trigger, decision] = entry.db.confirmation[0];
    if (String(record.confirmation.stepNo) !== stepNo || record.confirmation.trigger !== trigger || (record.confirmation.decision ?? '') !== decision) {
      report.problems.push(`${entry.key}: HTTP confirmation ≠ DB ${JSON.stringify(entry.db.confirmation[0])}`);
    }
  }
}

async function agentCase(page, key, call) {
  const entry = { key, steps: [] };
  report.runs.push(entry);
  await page.goto(`${base}/simulate/agent/${key}/review?lng=ko`, { waitUntil: 'networkidle' });
  await page.getByRole('radio', { name: call }).click();
  await (await enabled(page, '에이전트 실행')).click();
  await page.waitForURL(`**/simulate/agent/${key}/live**`, { timeout: 60000 });
  entry.steps.push(`live opened ${new Date().toISOString()}`);
  const deadline = Date.now() + 300000;
  let done = false;
  while (Date.now() < deadline) {
    if (await page.getByRole('link', { name: '결과 · 판정 근거' }).count()) {
      done = true;
      break;
    }
    const approve = page.getByRole('button', { name: '승인', exact: true });
    if ((await approve.count()) && (await approve.isEnabled())) {
      entry.asked = await page.getByRole('region', { name: /위임자 확인/ }).first().innerText();
      await approve.click();
      entry.steps.push(`delegator approved ${new Date().toISOString()}`);
      await page.waitForTimeout(1500);
      entry.answered = await page.getByRole('region', { name: /위임자 확인/ }).first().innerText();
    }
    if (await page.getByText('에이전트 작업을 끝내지 못했습니다', { exact: false }).count()) {
      entry.steps.push('run ended without its work');
      break;
    }
    await page.waitForTimeout(1000);
  }
  await page.screenshot({ path: join(out, `${key}-live-1440.png`), fullPage: true });
  if (!done) {
    report.problems.push(`${key}: the result did not open within 300 s`);
    return;
  }
  const href = await page.getByRole('link', { name: '결과 · 판정 근거' }).getAttribute('href');
  entry.runId = new URL(href, base).searchParams.get('run');
  entry.liveRows = await page.getByRole('table', { name: '에이전트가 보낸 요청' }).locator('tbody tr').count();
  await page.getByRole('link', { name: '결과 · 판정 근거' }).click();
  await page.waitForURL(`**/simulate/agent/${key}/result**`);
  const heading = page.getByRole('heading', { level: 1 });
  await heading.waitFor();
  await page.waitForTimeout(2000);
  entry.conclusion = (await heading.innerText()).trim();
  entry.side = await page.locator('dl').first().innerText();
  entry.resultRows = await page.getByRole('table', { name: '에이전트가 보낸 요청' }).locator('tbody tr').count();
  entry.controls = await page.getByRole('region', { name: '통제별 결과' }).locator('tbody tr').allInnerTexts();
  await shots(page, `${key}-result`);
  const record = await json(page, `/api/runs/${entry.runId}/agent`);
  entry.http = {
    sent: record.proof?.sent ?? null,
    steps: record.steps?.length ?? null,
    firstStopD: record.proof?.controls?.D?.firstStopStep ?? null,
    confirmation: record.confirmation
      ? { stepNo: record.confirmation.stepNo, trigger: record.confirmation.trigger, decision: record.confirmation.decision }
      : null,
    stopReason: record.stopReason,
  };
  compareAgent(entry, record);
  if (entry.resultRows !== record.steps.length) {
    report.problems.push(`${key}: screen rows ${entry.resultRows} ≠ HTTP steps ${record.steps.length}`);
  }
}

async function burst(page) {
  const entry = { key: 'BURST', steps: [] };
  report.runs.push(entry);
  await page.goto(`${base}/simulate/surge?lng=ko`, { waitUntil: 'networkidle' });
  await (await enabled(page, '10건 동시 전송')).click();
  const dialog = page.getByRole('dialog');
  await dialog.waitFor();
  await dialog.getByRole('button', { name: '10건 동시 전송' }).click();
  entry.steps.push(`sent ${new Date().toISOString()}`);
  const deadline = Date.now() + 360000;
  let done = false;
  while (Date.now() < deadline) {
    if (await page.getByRole('columnheader', { name: /내 전송/ }).count()) {
      done = true;
      break;
    }
    if (await page.getByText('이번 실행은 끝까지 가지 못했습니다', { exact: false }).count()) {
      entry.steps.push('burst failed');
      break;
    }
    if (!entry.counting && (await page.getByText('기록 저장 뒤 표시').count())) {
      entry.counting = await page.locator('dl').first().innerText();
      await page.screenshot({ path: join(out, 'BURST-live-1440.png'), fullPage: true });
    }
    await page.waitForTimeout(1500);
  }
  const current = await json(page, '/api/live/runs/current');
  entry.runId = current.runId ?? null;
  if (!done || !entry.runId) {
    report.problems.push('BURST: the own result did not show within 360 s');
    return;
  }
  await page.waitForTimeout(1000);
  const table = page.getByRole('table', { name: '판정 통합 결과' });
  entry.ownColumn = await table.locator('tbody tr').evaluateAll((rows) =>
    rows.map((row) => [row.querySelector('th')?.textContent, row.querySelectorAll('td')[0]?.textContent]),
  );
  await shots(page, 'BURST-result');
  const record = await json(page, `/api/runs/${entry.runId}/agent`);
  entry.http = record.burst ?? null;
  const steps = db(`select count(distinct step_no), count(*) filter (where outcome = 'DELIVERED') from run_arm_result where run_id = '${entry.runId}' and control = 'D';`)[0];
  const verdicts = db(`select count(*) filter (where final_action is not null), coalesce(sum(model_calls), 0) from run_decision where run_id = '${entry.runId}';`)[0];
  entry.db = { requests: Number(steps[0]), delivered: Number(steps[1]), withVerdict: Number(verdicts[0]), modelCalls: Number(verdicts[1]) };
  for (const name of ['requests', 'delivered', 'withVerdict', 'modelCalls']) {
    if (entry.http && entry.http[name] !== entry.db[name]) {
      report.problems.push(`BURST ${name}: HTTP ${entry.http[name]} ≠ DB ${entry.db[name]}`);
    }
  }
  const screen = Object.fromEntries(entry.ownColumn.map(([label, value]) => [label, Number(String(value).replace(/,/g, ''))]));
  const labels = { requests: '보낸 요청', delivered: '전달', refused: '거부', busy: '분석 중이라 거부', withVerdict: '자체 판정이 있는 요청', modelCalls: '모델 호출' };
  for (const [name, label] of Object.entries(labels)) {
    if (entry.http && screen[label] !== entry.http[name]) {
      report.problems.push(`BURST ${name}: screen ${screen[label]} ≠ HTTP ${entry.http[name]}`);
    }
  }
}

async function lab(page) {
  const entry = { key: 'LAB', steps: [] };
  report.runs.push(entry);
  await page.goto(`${base}/simulate/policy?tab=compose&case=S13T&field=items&to=40&lng=ko`, { waitUntil: 'networkidle' });
  await page.getByRole('table', { name: '전송 전 비교' }).waitFor({ timeout: 30000 }).catch(() => undefined);
  entry.before = await page.getByRole('region', { name: /전송 전 비교/ }).innerText().catch(() => null);
  await page.getByRole('radio', { name: '정상 업무' }).click();
  await (await enabled(page, '조건을 바꿔 실행')).click();
  await page.waitForURL('**sent=**', { timeout: 60000 });
  entry.steps.push(`sent ${new Date().toISOString()}`);
  const deadline = Date.now() + 300000;
  let done = false;
  while (Date.now() < deadline) {
    if (await page.getByRole('region', { name: /결과 비교/ }).count()) {
      done = true;
      break;
    }
    await page.waitForTimeout(1500);
  }
  if (!done) {
    report.problems.push('LAB: the result did not show within 300 s');
    await page.screenshot({ path: join(out, 'LAB-stopped.png'), fullPage: true });
    return;
  }
  await page.waitForTimeout(2500);
  const current = await json(page, '/api/live/runs/current');
  entry.runId = current.runId ?? null;
  entry.result = await page.getByRole('region', { name: /결과 비교/ }).innerText();
  await shots(page, 'LAB-result');
  const recent = await json(page, '/api/lab/runs/recent');
  const mine = Array.isArray(recent) ? recent.find((item) => item.runId === entry.runId) : null;
  entry.against = mine?.referenceRunId ?? null;
  if (entry.runId && entry.against) {
    const versus = await json(page, `/api/runs/${entry.runId}/versus?against=${entry.against}`);
    entry.http = { now: versus.now?.business, nowAction: versus.now?.engineAction, before: versus.before?.business };
  }
  entry.db = {
    composition: db(`select case_key, designed, changed, conditions from lab_composition where run_id = '${entry.runId}';`)[0] ?? null,
    arms: db(`select control, outcome, delivered_items from run_arm_result where run_id = '${entry.runId}' and step_no = 1 order by control;`),
    decision: db(`select final_action, total_analysis_ms from run_decision where run_id = '${entry.runId}' and step_no = 1;`)[0] ?? null,
  };
  if (entry.http && entry.db.decision && entry.http.nowAction !== entry.db.decision[0]) {
    report.problems.push(`LAB: HTTP action ${entry.http.nowAction} ≠ DB ${entry.db.decision[0]}`);
  }
}

try {
  const first = await visitor();
  if (only.includes('T5')) await agentCase(first, 'T5', /중단 · 위임자 확인/);
  if (only.includes('N1')) await agentCase(first, 'N1', /^처리/);
  const second = await visitor();
  if (only.includes('BURST')) await burst(second);
  if (only.includes('LAB')) await lab(second);
} catch (error) {
  report.problems.push(`stopped: ${error.message}`);
} finally {
  report.finishedAt = new Date().toISOString();
  writeFileSync(join(out, 'real-run-report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(JSON.stringify({ runs: report.runs.map((run) => ({ key: run.key, runId: run.runId, conclusion: run.conclusion, steps: run.steps })), problems: report.problems }, null, 2));
