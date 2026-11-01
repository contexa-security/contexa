// UX-R1 I-6 real-record check (완료판정기준 I-6): no new run. The standard benchmarks' result bundle is rebuilt from the
// pinned report files and must equal the file the web serves; the standard-benchmark screens and the start-of-demo band
// must show the bundle's values; the scenario validation must show the portal's counts (HTTP), which the portal
// database agrees with; and no screen of the standard benchmarks may claim a certification (PC-9).
//
//   node ux_real_i6.mjs --web http://localhost:5180 --api http://127.0.0.1:19180 --out <dir>
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const require = createRequire('E:/projects/contexa/contexa-showcase/web/package.json');
const { chromium } = require('playwright');

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index > 0 ? process.argv[index + 1] : fallback;
}
const web = arg('web', 'http://localhost:5180');
const api = arg('api', 'http://127.0.0.1:19180');
const out = arg('out', '.').replace(/^\/([a-z])\//i, (_, drive) => `${drive.toUpperCase()}:/`);
mkdirSync(out, { recursive: true });

const BENCH = 'E:/projects/contexa-benchmark';
const SERVED = 'E:/projects/contexa/contexa-showcase/web/public/data/benchmarks/bundle-v1.json';
const REBUILT = join(out, 'bundle-rebuilt.json');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

function db(sql) {
  const text = execFileSync(
    'docker',
    ['exec', '-i', 'contexa-showcase-postgres-1', 'sh', '-c', 'psql -U "$POSTGRES_USER" -d showcase_portal -At -F "|"'],
    { input: sql, encoding: 'utf8' },
  );
  return text.split('\n').filter(Boolean).map((line) => line.split('|'));
}

const report = { web, api, startedAt: new Date().toISOString(), checks: [], problems: [] };
function check(area, name, screen, expected) {
  const same = JSON.stringify(screen) === JSON.stringify(expected);
  report.checks.push({ area, name, screen, expected, same });
  if (!same) {
    report.problems.push(`${area} · ${name}: screen ${JSON.stringify(screen)} ≠ ${JSON.stringify(expected)}`);
  }
}

// ── 1. The bundle: rebuilt from the pinned report files, the same bytes as the file the web serves ────────────────
const built = execFileSync(`${BENCH}/.venv/Scripts/python.exe`, ['-X', 'utf8', 'bench/publish_bundle.py', '--out', REBUILT], {
  cwd: BENCH,
  encoding: 'utf8',
});
report.rebuilt = built.trim();
const served = readFileSync(SERVED);
check('bundle', 'rebuilt bytes = served file', sha(readFileSync(REBUILT)), sha(served));
const bundle = JSON.parse(served.toString('utf8'));

const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR' })).newPage();
page.setDefaultTimeout(60000);
const fetched = await page.request.get(`${web}/data/benchmarks/bundle-v1.json`);
check('bundle', 'web serves the bundle file', sha(await fetched.body()), sha(served));

const pct = (rate, digits) => `${new Intl.NumberFormat('ko-KR', { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(rate * 100)}%`;
const digitsOf = (bench) => (bench === 'agentdojo' ? 2 : 1);
const banned = /인증받|인정받|공인|certif|accredit|endors/i;

async function shots(name) {
  await page.screenshot({ path: join(out, `${name}-1440.png`), fullPage: true });
  await page.setViewportSize({ width: 390, height: 900 });
  await page.waitForTimeout(400);
  await page.screenshot({ path: join(out, `${name}-390.png`), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.waitForTimeout(400);
}

// ── 2. The standard benchmarks: every matrix row, the summary strip and the limits = the bundle ───────────────────
await page.goto(`${web}/benchmarks`);
const matrix = page.getByRole('table', { name: '결과 행렬' });
await matrix.waitFor();
for (const bench of bundle.benchmarks) {
  for (const test of bench.tests.filter((item) => item.matrix)) {
    const row = matrix.locator('tbody tr').filter({ has: page.getByRole('rowheader', { name: test.label.ko }) }).first();
    const text = (await row.innerText()).replace(/\s+/g, ' ');
    check('benchmarks', `${test.id} protected`, text.includes(pct(test.protected.rate, digitsOf(bench.id))), true);
    check('benchmarks', `${test.id} unprotected`, text.includes(pct(test.unprotected.rate, digitsOf(bench.id))), true);
    check('benchmarks', `${test.id} sample`, text.includes(new Intl.NumberFormat('ko-KR').format(test.sample)), true);
  }
}
const strip = (await page.getByLabel('측정 요약').innerText()).replace(/\s+/g, ' ');
check('benchmarks', 'frozen versions', strip.includes(`${bundle.freezes.length}판`), true);
check('benchmarks', 'programme spend', strip.includes(`$${bundle.program.spendUsd.toFixed(2)}`), true);
check('benchmarks', 'limits listed', await page.getByRole('region', { name: '한계 — 이 결과가 말하지 않는 것' }).getByRole('listitem').count(), bundle.limits.length);
await shots('benchmarks');
const pages = ['/benchmarks', '/benchmarks/agentdojo', '/benchmarks/injecagent', '/benchmarks/promptfoo', '/benchmarks/method'];
const tabs = ['results', 'breakdown', 'variants', 'cases', 'settings'];
for (const path of pages) {
  const addresses = path === '/benchmarks' || path === '/benchmarks/method' ? [path] : tabs.map((tab) => `${path}?tab=${tab}`);
  for (const address of addresses) {
    console.log('PC-9', address);
    await page.goto(`${web}${address}`);
    await page.locator('h1').first().waitFor();
    await page.waitForLoadState('networkidle');
    const words = await page.locator('main').innerText();
    check('PC-9', `${address} free of certification claims`, banned.test(words), false);
  }
}
await page.goto(`${web}/benchmarks/agentdojo?tab=cases`);
await page.getByRole('heading', { name: /보호를 켜고도 성공한 공격/ }).first().waitFor();
const agentdojo = bundle.benchmarks.find((bench) => bench.id === 'agentdojo');
for (const [test, rows] of Object.entries(agentdojo.cases)) {
  check('benchmarks', `${test} cases listed`, (await page.getByRole('heading', { name: new RegExp(`보호를 켜고도 성공한 공격 ${rows.length}건`) }).count()) > 0, true);
}
await shots('benchmarks-agentdojo-cases');

console.log('section', '3.');
// ── 3. The start of the demo: the band's three results = the bundle's headline ───────────────────────────────────
await page.goto(`${web}/`);
const band = page.getByRole('region', { name: '표준 벤치마크' });
await band.waitFor();
const bandText = (await band.innerText()).replace(/\s+/g, ' ');
for (const headline of bundle.headline) {
  const bench = bundle.benchmarks.find((item) => item.id === headline.benchmark);
  const test = bench.tests.find((item) => item.id === headline.test);
  check('home band', `${headline.test} unprotected → protected`, bandText.includes(pct(test.unprotected.rate, digitsOf(bench.id))) && bandText.includes(pct(test.protected.rate, digitsOf(bench.id))), true);
  check('home band', `${headline.test} condition`, bandText.includes(test.label.ko), true);
}
check('PC-9', 'home band free of certification claims', banned.test(bandText), false);
await band.screenshot({ path: join(out, 'home-band-1440.png') });

console.log('section', '4.');
// ── 4. The scenario validation = the portal's counts (HTTP), the database agreeing on the runs ────────────────────
const benchmark = await (await page.request.get(`${api}/api/benchmark`)).json();
const contexa = benchmark.controls.find((score) => score.control === 'D');
await page.goto(`${web}/validation`);
await page.getByRole('table', { name: '보안 통제별 결과' }).waitFor();
const summary = (await page.locator('main').innerText()).replace(/\s+/g, ' ');
check('validation', 'threat runs', summary.includes(`위협 시나리오 실행 ${benchmark.scope.attackRuns}`), true);
check('validation', 'Contexa missed', summary.includes(`Contexa 미탐 ${contexa.missed}회`), true);
check('validation', 'scope line runs', summary.includes(`모두 ${benchmark.scope.runs}회 보냈습니다`), true);
for (const score of benchmark.controls) {
  const row = page.getByRole('table', { name: '보안 통제별 결과' }).locator('tbody tr').nth(['A', 'B', 'C1', 'C2', 'D'].indexOf(score.control));
  check('validation', `${score.control} missed · false positives`, (await row.innerText()).includes(`미탐 ${score.missed} · 오탐 ${score.falseBlock.hits}`), true);
}
const protocol = benchmark.scope.protocols[0]?.protocolId;
const counted = Number(db(`select count(*) from run where protocol_id = '${protocol}' and status = 'COMPLETED' and setting_hash = '${benchmark.spec.settingHash}';`)[0][0]);
check('validation', 'runs in the database = the measurement scope', counted, benchmark.scope.runs);
await shots('validation-summary');
await page.goto(`${web}/validation?tab=controls`);
const rates = page.getByRole('table', { name: '보안 통제별 탐지율 · 오탐률' });
await rates.waitFor();
const contexaRow = (await rates.locator('tbody tr').nth(4).innerText()).replace(/\s+/g, ' ');
check('validation', 'Contexa detection', contexaRow.includes(`${contexa.stoppedAny.hits} / ${contexa.stoppedAny.total}`), true);
check('validation', 'Contexa false positives', contexaRow.includes(`${contexa.falseBlock.hits} / ${contexa.falseBlock.total}`), true);
await page.goto(`${web}/validation?tab=quality`);
await page.getByRole('heading', { name: `위협 ${benchmark.scope.attackRuns}회 판정 결과` }).waitFor();
check('validation', 'judgment-time bins', await page.getByLabel('판정 시간 구간별 판정 수').locator('li').count(), benchmark.engine.analysisBins.length);
const decisions = Number(db(`select count(*) from run_decision d join run r on r.run_id = d.run_id where r.protocol_id = '${protocol}' and r.status = 'COMPLETED' and r.setting_hash = '${benchmark.spec.settingHash}' and d.final_action is not null;`)[0][0]);
report.dbDecisions = decisions;
check('validation', 'decisions: HTTP engine = database decisions with an action', benchmark.engine.decisions, decisions);
await shots('validation-quality');
const agent = await (await page.request.get(`${api}/api/benchmark/agent`)).json();
await page.goto(`${web}/validation?tab=agent`);
await page.getByRole('table', { name: '경로별 결과' }).waitFor();
check('validation', 'agent paths', await page.getByRole('table', { name: '경로별 결과' }).locator('tbody tr').count(), agent.byPath.length + 1);
await shots('validation-agent');

report.finishedAt = new Date().toISOString();
report.summary = { checks: report.checks.length, same: report.checks.filter((found) => found.same).length, problems: report.problems.length };
writeFileSync(join(out, 'real-record-report.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report.summary));
for (const problem of report.problems) {
  console.log('PROBLEM', problem);
}
await browser.close();
