// UX-R1 I-5 real-record check (완료판정기준 I-5): no new run. The decision log, the decision details, the AI decision
// engine and the comparison are opened on the real portal's records and each value on the screen is compared with the
// portal's HTTP answers and its database rows. Reads only (GET and database selects); no model call, no cost.
//
//   node ux_real_i5.mjs --web http://localhost:5180 --api http://127.0.0.1:19180 --out <dir>
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const require = createRequire('E:/projects/contexa/contexa-showcase/web/package.json');
const { chromium } = require('playwright');

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index > 0 ? process.argv[index + 1] : fallback;
}
const web = arg('web', 'http://127.0.0.1:19180');
const api = arg('api', 'http://127.0.0.1:19180');
const out = arg('out', '.').replace(/^\/([a-z])\//i, (_, drive) => `${drive.toUpperCase()}:/`);
mkdirSync(out, { recursive: true });

const ko = JSON.parse(readFileSync('E:/projects/contexa/contexa-showcase/web/src/i18n/ko.json', 'utf8'));
const VERDICT = { ALLOW: 'ux.verdict.allow', CHALLENGE: 'ux.verdict.stepup', ESCALATE: 'ux.verdict.hold', BLOCK: 'ux.verdict.block' };
const verdictWord = (action) => ko[VERDICT[action] ?? 'ux.verdict.none'];
const RESTRICTIVE = new Set(['CHALLENGE', 'ESCALATE', 'BLOCK']);
const STOPPING = new Set(['STOPPED', 'HALTED', 'PARTLY_STOPPED']);
const number = (value, digits) =>
  new Intl.NumberFormat('ko-KR', digits === undefined ? {} : { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(value);
const seconds = (ms) => ko['ux.time.seconds'].replace('{{value}}', number(ms / 1000, ms < 1000 ? 3 : 1));

/** Rows of the portal database (container contexa-showcase-postgres-1), never secrets. */
function db(sql) {
  const text = execFileSync(
    'docker',
    ['exec', '-i', 'contexa-showcase-postgres-1', 'sh', '-c', 'psql -U "$POSTGRES_USER" -d showcase_portal -At -F "|"'],
    { input: sql, encoding: 'utf8' },
  );
  return text.split('\n').filter(Boolean).map((line) => line.split('|'));
}
const quoted = (ids) => ids.map((id) => `'${id.replace(/[^a-z0-9-]/gi, '')}'`).join(',');

async function get(path) {
  const response = await fetch(`${api}${path}`);
  if (!response.ok) {
    throw new Error(`${path} → HTTP ${response.status}`);
  }
  return response.json();
}

/** The decisions of a run in the database, and the request it was decided at (the first restriction, else the last). */
function decisions(runId) {
  const rows = db(
    `select step_no, coalesce(final_action, ''), risk_score, confidence, total_analysis_ms, model_calls from run_decision where run_id = '${runId}' order by step_no;`,
  ).map(([step, action, risk, confidence, ms, calls]) => ({
    step: Number(step),
    action: action || null,
    risk: risk === '' ? null : Number(risk),
    confidence: confidence === '' ? null : Number(confidence),
    ms: ms === '' ? null : Number(ms),
    calls: calls === '' ? null : Number(calls),
  }));
  const deciding = rows.find((row) => RESTRICTIVE.has(row.action ?? '')) ?? rows[rows.length - 1] ?? null;
  return { rows, deciding };
}

const report = { web, api, startedAt: new Date().toISOString(), checks: [], problems: [] };
function check(area, name, screen, expected) {
  const same = JSON.stringify(screen) === JSON.stringify(expected);
  report.checks.push({ area, name, screen, expected, same });
  if (!same) {
    report.problems.push(`${area} · ${name}: screen ${JSON.stringify(screen)} ≠ ${JSON.stringify(expected)}`);
  }
}

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR' });
const page = await context.newPage();
page.setDefaultTimeout(60000);

async function shots(name) {
  await page.screenshot({ path: join(out, `${name}-1440.png`), fullPage: true });
  await page.setViewportSize({ width: 390, height: 900 });
  await page.waitForTimeout(400);
  await page.screenshot({ path: join(out, `${name}-390.png`), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.waitForTimeout(400);
}

// ── 1. The decision log: the three sources, each run once (DEC-40) ─────────────────────────────────────────────────
const hook = await get('/api/hook');
const pairs = await get('/api/pairs');
const replays = await Promise.all(pairs.filter((pair) => pair.recorded).map((pair) => get(`/api/replays/${pair.key}`)));
const measured = await get('/api/benchmark/runs');
const publicIds = [...new Set([hook.attacker.runId, hook.owner.runId, ...replays.flatMap((replay) => replay.scenes.map((scene) => scene.runId))])];
const measuredOnly = measured.runs.map((run) => run.runId).filter((id) => !publicIds.includes(id));
const everyId = [...publicIds, ...measuredOnly];
report.log = { public: publicIds.length, measured: measured.runs.length, measuredOnly: measuredOnly.length, union: everyId.length };
check('log', 'runs of the three sources found in the database', Number(db(`select count(*) from run where run_id in (${quoted(everyId)});`)[0][0]), everyId.length);

async function logTotal(query) {
  await page.goto(`${web}/runs${query}`);
  await page.getByRole('table', { name: ko['ux.runs.title'] }).waitFor();
  const pager = page.getByRole('navigation', { name: ko['ux.runs.pages'] });
  await page.waitForFunction(() => /전체 [\d,]+건/.test(document.body.innerText));
  const text = await pager.innerText();
  return Number(text.match(/전체 ([\d,]+)건/)[1].replace(/,/g, ''));
}
check('log', 'all rows (a new visitor has no run of its own)', await logTotal(''), everyId.length);
check('log', 'public recorded rows', await logTotal('?source=public'), publicIds.length);
check('log', 'measured rows', await logTotal('?source=measured'), measuredOnly.length);

// The first page's ten rows: the verdict and the decision time at the deciding request, the existing controls' stops.
await page.goto(`${web}/runs`);
const table = page.getByRole('table', { name: ko['ux.runs.title'] });
await table.waitFor();
await page.waitForFunction(
  (name) => {
    const found = [...document.querySelectorAll('table')].find((t) => t.querySelector('caption')?.textContent === name);
    const rows = found ? [...found.querySelectorAll('tbody tr')] : [];
    return rows.length > 0 && rows.every((row) => ![...row.cells].some((cell) => cell.textContent?.trim() === '…'));
  },
  ko['ux.runs.title'],
);
const rows = await table.locator('tbody tr').evaluateAll((trs) => trs.map((tr) => [...tr.cells].map((cell) => cell.innerText.trim())));
report.firstPage = [];
for (const cells of rows) {
  const runId = cells[1].match(/run-[0-9a-f]+/)?.[0];
  const { deciding } = decisions(runId);
  const score = await get(`/api/runs/${runId}/score`);
  const stops = ['A', 'B', 'C1', 'C2'].filter((control) => STOPPING.has(score.business[control]?.result ?? '')).length;
  report.firstPage.push({ runId, cells, decidingStep: deciding?.step ?? null });
  check('log row', `${runId} verdict`, cells[2], verdictWord(deciding?.action));
  check('log row', `${runId} decision time`, cells[5], deciding?.ms != null ? seconds(deciding.ms) : '—');
  check('log row', `${runId} existing controls that stopped`, cells[4], `${stops} / 4`);
}
await page.goto(`${web}/runs?run=${hook.attacker.runId}`);
await page.getByRole('complementary').getByText(/위험도 \d/).waitFor();
await shots('runs-panel');

// ── 2. The decision details of three runs: the public recording, a measured run of several requests, a normal one ──
const multi = measured.runs.find((run) => !publicIds.includes(run.runId) && run.executedSteps > 1);
const normal = measured.runs.find((run) => !publicIds.includes(run.runId) && run.truth.classification === 'NORMAL');
const samples = [hook.attacker.runId, multi?.runId, normal?.runId].filter(Boolean);
report.details = [];
for (const runId of samples) {
  const { rows: steps, deciding } = decisions(runId);
  await page.goto(`${web}/runs/${runId}`);
  await page.getByRole('heading', { level: 1, name: runId }).waitFor();
  const strip = page.getByLabel(ko['ux.detail.strip'], { exact: true });
  await strip.waitFor();
  const cells = Object.fromEntries(
    await strip.locator('div').evaluateAll((divs) => divs.map((div) => [div.querySelector('dt')?.innerText.trim(), div.querySelector('dd')?.innerText.trim()])),
  );
  const title = await page.locator('h1').locator('xpath=..').innerText();
  const status = title.replace(runId, '').trim();
  const anatomy = await get(`/api/runs/${runId}/steps/${deciding?.step ?? 1}/anatomy`);
  const recorded = anatomy.interpretation.recorded;
  report.details.push({ runId, steps: steps.length, decidingStep: deciding?.step ?? null, cells, status });
  check('detail', `${runId} verdict`, status, verdictWord(deciding?.action));
  check('detail', `${runId} verdict (HTTP)`, recorded.finalAction, deciding?.action ?? null);
  check(
    'detail',
    `${runId} risk · confidence`,
    cells[ko['ux.detail.strip.scores']],
    deciding?.risk != null ? `${deciding.risk.toFixed(2)} · ${deciding.confidence?.toFixed(2) ?? '—'}` : '—',
  );
  check('detail', `${runId} decision time`, cells[ko['ux.detail.strip.time']]?.split(' · ')[0], deciding?.ms != null ? seconds(deciding.ms) : '—');
  check('detail', `${runId} decision time (HTTP)`, anatomy.interpretation.timings?.totalAnalysisMs ?? null, deciding?.ms ?? null);
  check('detail', `${runId} request path`, cells[ko['ux.detail.strip.request']]?.includes(anatomy.context.resource?.requestPath ?? anatomy.operation), true);
  if (steps.length > 1) {
    const chosen = await page.getByRole('navigation', { name: ko['ux.detail.steps'] }).locator('[aria-current="page"]').innerText();
    check('detail', `${runId} request shown first = the deciding request`, chosen, `요청 ${deciding.step}`);
  }
  await shots(`detail-${runId === hook.attacker.runId ? 'public' : runId === multi?.runId ? 'multi' : 'normal'}`);
}

// The integrity check of the public recording, as it stands (DEC-43).
const quality = await get(`/api/runs/${hook.attacker.runId}/steps/1/quality`);
await page.goto(`${web}/runs/${hook.attacker.runId}?tab=integrity`);
const inspection = page.getByRole('region', { name: ko['ux.detail.integrity.inspection'] });
await inspection.locator('tbody tr').first().waitFor();
const inspected = await inspection.locator('tbody tr').evaluateAll((trs) => trs.map((tr) => [...tr.cells].map((cell) => cell.innerText.trim())));
check('integrity', 'inspection verdict', (await inspection.locator('p').first().innerText()).split('\n')[0].trim(), ko[`ux.detail.integrity.verdict.${quality.inspection.verdict}`]);
check(
  'integrity',
  'checks (matched · mismatched · unverifiable)',
  inspected.map((cells) => cells.slice(1).map(Number)),
  quality.inspection.checks.map((found) => [found.matched, found.mismatched, found.unverifiable]),
);
check('integrity', 'package id', (await page.getByRole('region', { name: ko['ux.detail.integrity.seal'] }).innerText()).includes(quality.seal.packageId), true);
await shots('detail-integrity');

// ── 3. The AI decision engine on the public recording (a new visitor has no run of its own, DEC-45) ───────────────
const engineRun = hook.attacker.runId;
const engineAnatomy = await get(`/api/runs/${engineRun}/steps/1/anatomy`);
const engineDb = decisions(engineRun).rows.find((row) => row.step === 1);
await page.goto(`${web}/engine`);
await page.getByText(ko['ux.engine.base.public'] ? ko['ux.engine.base.public'] : '공개 녹화', { exact: false }).first().waitFor();
const stages = page.locator('section[aria-labelledby="engine-flow"] ol > li');
await page.waitForFunction(() => {
  const items = [...document.querySelectorAll('section[aria-labelledby="engine-flow"] ol > li')];
  return items.length === 7 && items.every((li) => !li.innerText.includes('…\n') && !/^…$/m.test(li.innerText));
});
const stageText = await stages.evaluateAll((items) => items.map((li) => li.innerText.replace(/\s+/g, ' ').trim()));
const head = (await page.locator('section[aria-labelledby="engine-flow"] header').innerText()).replace(/\s+/g, ' ');
const figures = engineAnatomy.figures;
const lines = engineAnatomy.promptLines;
const calls = engineAnatomy.interpretation.calls;
report.engine = { runId: engineRun, head, stages: stageText };
check('engine', 'stage count', stageText.length, 7);
check('engine', 'learning: requests learned', stageText[0].includes(`학습 요청 ${number(figures.baselineBefore)}건`), true);
check('engine', 'learning: observations compared', stageText[0].includes(`${number(figures.workProfileObservations ?? 0)}건과 비교`), true);
check(
  'engine',
  'prompt lines',
  stageText[3].includes(`시스템 규칙 ${number(lines.system)}줄 + 상황 ${number(lines.user)}줄 = ${number(lines.total)}줄`),
  true,
);
check('engine', 'model calls (screen)', stageText[4].includes(`호출 ${number(calls.length)}회`), true);
check('engine', 'model calls (HTTP = DB)', calls.length, engineDb?.calls ?? null);
check(
  'engine',
  'prompt tokens',
  stageText[4].includes(`입력 ${number(calls.reduce((sum, call) => sum + (call.promptTokens ?? 0), 0))} 토큰`),
  true,
);
check('engine', 'model', stageText[4].includes(calls[0]?.model ?? '—'), true);
check('engine', 'verdict', head.includes(verdictWord(engineDb?.action)), true);
check('engine', 'total time', head.includes(ko['ux.engine.total'].replace('{{seconds}}', number(engineDb.ms / 1000, engineDb.ms < 1000 ? 3 : 1))), true);
const engineQuality = await get(`/api/runs/${engineRun}/steps/1/quality`);
const sum = (key) => engineQuality.inspection.checks.reduce((total, found) => total + found[key], 0);
const seal = (await page.getByRole('region', { name: '무결성 봉인' }).innerText()).replace(/\s+/g, ' ');
check('engine', 'seal counts', seal.includes(`일치 ${number(sum('matched'))} · 불일치 ${number(sum('mismatched'))} · 확인 불가 ${number(sum('unverifiable'))}`), true);
await shots('engine-flow');

// ── 4. The comparison's measured runs: one dot per run and control, attacks and normal work apart (ST-53) ─────────
const bench = await get('/api/benchmark');
await page.goto(`${web}/compare?tab=runs`);
await page.getByRole('list', { name: `${ko['ux.control.D']} · ${ko['ux.runs.kind.THREAT']}` }).waitFor();
const dotIds = new Set();
report.dots = {};
// The screen draws the two rules and Contexa, as the old 5-4 screen did (pages/main/RunsPage.tsx).
for (const control of ['C1', 'C2', 'D']) {
  for (const kind of ['THREAT', 'NORMAL']) {
    const list = page.getByRole('list', { name: `${ko[`ux.control.${control}`]} · ${ko[`ux.runs.kind.${kind}`]}` });
    const hrefs = await list.getByRole('link').evaluateAll((links) => links.map((link) => link.getAttribute('href')));
    const expected = bench.cases
      .filter((found) => found.classification === kind)
      .flatMap((found) => Object.entries(found.runResults ?? {}).filter(([, results]) => results[control]).map(([runId]) => runId));
    hrefs.forEach((href) => dotIds.add(decodeURIComponent(href.replace('/runs/', ''))));
    report.dots[`${control}.${kind}`] = hrefs.length;
    check('compare', `${control} · ${kind} dots`, hrefs.map((href) => decodeURIComponent(href.replace('/runs/', ''))).sort(), expected.sort());
  }
  // The control's row: the parent of its attack list (the class names are hashed).
  const row = page.getByRole('list', { name: `${ko[`ux.control.${control}`]} · ${ko['ux.runs.kind.THREAT']}` }).locator('xpath=..');
  const total = bench.controls.find((found) => found.control === control);
  check(
    'compare',
    `${control} totals`,
    // The words as the dictionary has them now (I-8 renamed them "미탐 n · 오탐 n").
    (await row.innerText()).includes(
      ko['ux.compareMenu.runs.total']
        .replace('{{missed}}', number(total.missed))
        .replace('{{blocked}}', number(total.falseBlock.hits)),
    ),
    true,
  );
}
check('compare', 'dot runs found in the database', Number(db(`select count(*) from run where run_id in (${quoted([...dotIds])});`)[0][0]), dotIds.size);
await shots('compare-runs');

report.finishedAt = new Date().toISOString();
report.summary = { checks: report.checks.length, same: report.checks.filter((found) => found.same).length, problems: report.problems.length };
writeFileSync(join(out, 'real-record-report.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report.summary));
for (const problem of report.problems) {
  console.log('PROBLEM', problem);
}
await browser.close();
