// UX-R1 I-7 real-record check (완료판정기준 I-7): no new run. The operational metrics and the adoption guide must show
// the portal's answers of the same moment (/api/stats, /api/settings, /api/benchmark), the database must agree on the
// counted runs and decisions (the server's own conditions), the tour must play files the web serves, the privacy page
// must name the cookies the portal sets, and the glossary and the old addresses must lead where they should.
//
//   node ux_real_i7.mjs --web http://localhost:5181 --api http://127.0.0.1:19180 --out <dir>
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
const web = arg('web', 'http://localhost:5181');
const api = arg('api', 'http://127.0.0.1:19180');
const out = arg('out', '.').replace(/^\/([a-z])\//i, (_, drive) => `${drive.toUpperCase()}:/`);
mkdirSync(out, { recursive: true });

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
const has = (area, name, text, part) => check(area, name, text.includes(part) ? part : `(missing) ${part}`, part);

const n = (value) => new Intl.NumberFormat('ko-KR').format(value);
const one = (value) => new Intl.NumberFormat('ko-KR', { minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(value);
const utc = (iso) => new Date(iso).toISOString().slice(0, 16).replace('T', ' ');

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR' });
const page = await context.newPage();
page.setDefaultTimeout(60000);
const errors = [];
page.on('pageerror', (error) => errors.push(String(error?.message ?? error)));

async function shots(name) {
  await page.screenshot({ path: join(out, `${name}-1440.png`), fullPage: true });
  await page.setViewportSize({ width: 390, height: 900 });
  await page.waitForTimeout(400);
  await page.screenshot({ path: join(out, `${name}-390.png`), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.waitForTimeout(400);
}
async function open(address) {
  await page.goto(`${web}${address}`);
  await page.locator('h1').first().waitFor();
  await page.waitForLoadState('networkidle');
}
const text = async (locator) => (await locator.innerText()).replace(/\s+/g, ' ');

// ── 1. The operational metrics = /api/stats of the same moment, the database agreeing ─────────────────────────────
const stats = await (await page.request.get(`${api}/api/stats`)).json();
const counted = "r.forced_action is null and r.status = 'COMPLETED'";
const [[completed, failed, live]] = db(`select count(*) filter (where status = 'COMPLETED'), count(*) filter (where status = 'FAILED'), count(*) filter (where status = 'COMPLETED' and live_run) from run r where r.forced_action is null;`);
check('metrics · DB', 'completed runs', stats.runs.completed, Number(completed));
check('metrics · DB', 'failed runs', stats.runs.failed, Number(failed));
check('metrics · DB', 'visitor runs', stats.runs.live, Number(live));
const [[decisions]] = db(`select count(*) from run_decision d join run r on r.run_id = d.run_id where ${counted} and d.final_action is not null and not coalesce(d.unresolved, false);`);
check('metrics · DB', 'engine decisions', stats.engineDecisions, Number(decisions));
report.statsComputedAt = stats.computedAt;

await open('/metrics');
check('metrics', 'same snapshot (computed time)', (await text(page.locator('main'))).includes(`계산 시각 ${utc(stats.computedAt)}`), true);
const finished = stats.runs.completed + stats.runs.failed;
has('metrics', 'decisions card', await text(page.getByRole('group', { name: '판정', exact: true })), `${n(stats.engineDecisions)}건`);
has('metrics', 'median latency', await text(page.getByRole('group', { name: '판정 시간 중앙값' })), `${one(stats.decisionTime.p50Ms / 1000)}초`);
has('metrics', 'p95', await text(page.getByRole('group', { name: '판정 시간 중앙값' })), `p95 ${one(stats.decisionTime.p95Ms / 1000)}초`);
has('metrics', 'completed + failed share', await text(page.getByRole('group', { name: '완료 실행' })), `기술적 실패로 중단 ${n(stats.runs.failed)}회 · 끝난 실행의 ${one((stats.runs.failed / finished) * 100)}%`);
has('metrics', 'operator runs', await text(page.getByRole('group', { name: '방문자 실행' })), `나머지 ${n(stats.runs.completed - stats.runs.live)}회`);
const mix = await page.getByRole('list', { name: '판정 분포' }).getByRole('listitem').allInnerTexts();
check('metrics', 'decision mix', mix.map((item) => item.replace(/\s+/g, ' ').trim()), [
  `허용 ${n(stats.engineActions.ALLOW)}`,
  `추가 인증 ${n(stats.engineActions.CHALLENGE)}`,
  `검토 보류 ${n(stats.engineActions.ESCALATE)}`,
  `차단 ${n(stats.engineActions.BLOCK)}`,
]);
const uncounted = await text(page.getByRole('region', { name: '판정 수에 넣지 않은 요청' }));
has('metrics', 'reused prior decisions', uncounted, n(stats.unresolved.noNewAnalysis));
has('metrics', 'technical failures', uncounted, n(stats.unresolved.technical));
const settingsCard = await text(page.getByRole('region', { name: '운영 설정' }));
has('metrics', 'engine mode', settingsCard, stats.spec.effectiveMode);
has('metrics', 'specifications', settingsCard, `${n(stats.specCount)}종`);
has('metrics', 'agreement', settingsCard, `${n(stats.agreement.agreeing)} / ${n(stats.agreement.repetitions)}`);
await shots('metrics-overview');
await open('/metrics?tab=decisions');
const rows = await page.getByRole('table', { name: '판정별 수' }).locator('tbody tr').allInnerTexts();
const order = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'];
check('metrics', 'decision rows', rows.map((row) => row.replace(/\s+/g, '')), order.map((action) => {
  const label = { ALLOW: '허용', CHALLENGE: '추가인증', ESCALATE: '검토보류', BLOCK: '차단' }[action];
  return `${label}${n(stats.engineActions[action])}${one((stats.engineActions[action] / stats.engineDecisions) * 100)}%`;
}));
const after = await text(page.getByRole('region', { name: '검토 보류 · 차단 뒤의 처리' }));
has('metrics', 'held before the response', after, `검토 보류 ${n(stats.engineActions.ESCALATE)}건 가운데 ${n(stats.escalateHeld)}건`);
has('metrics', 'blocked after the hold expired', after, `${n(stats.blockedAfterReview)}건`);
await open('/metrics?tab=latency');
const end = Math.max(5, Math.ceil(stats.decisionTime.p95Ms / 5000) * 5);
check('metrics', 'latency strip', await page.getByRole('img', { name: /판정 시간 띠/ }).getAttribute('aria-label'), `판정 시간 띠: p50 ${one(stats.decisionTime.p50Ms / 1000)}초 · p95 ${one(stats.decisionTime.p95Ms / 1000)}초, 축 0~${n(end)}초`);
await open('/metrics?tab=runs');
const runsCard = await text(page.getByRole('region', { name: '실행', exact: true }));
has('metrics', 'today', runsCard, `오늘 방문자 실행(세계 표준시 자정부터) ${n(stats.runs.today)}회`);
has('metrics', 'first run', runsCard, utc(stats.runs.firstAt));
has('metrics', 'latest run', runsCard, utc(stats.runs.lastAt));
const scope = await text(page.getByRole('region', { name: '정답이 있는 실행' }));
for (const [label, value] of [['위협', stats.scope.threatRuns], ['정상 업무', stats.scope.normalRuns], ['정답 없음(점수 제외)', stats.scope.otherRuns]]) {
  has('metrics', `scope ${label}`, scope, `${label} ${n(value)}회`);
}
await shots('metrics-runs');
await open('/metrics?tab=agreement');
check('metrics', 'recordings listed', await page.getByRole('table', { name: '반복 판정 일치' }).locator('tbody tr').count(), stats.agreement.recordings.length);

// ── 2. The adoption guide = /api/stats, /api/settings, /api/benchmark ───────────────────────────────────────────────
const settings = await (await page.request.get(`${api}/api/settings`)).json();
const benchmark = await (await page.request.get(`${api}/api/benchmark`)).json();
const contexa = benchmark.controls.find((score) => score.control === 'D');
await open('/adopt');
has('adopt', 'dependency code', await text(page.getByRole('region', { name: '의존성 코드' })), 'implementation "ai.ctxa:spring-boot-starter-contexa:0.1.0"');
const roles = page.getByRole('region', { name: '역할별 도입 효과' });
await roles.getByText(/시나리오 검증의 정상 업무/).waitFor();
has('adopt', 'employee counts', await text(roles), `시나리오 검증의 정상 업무 ${n(contexa.falseBlock.total)}회 가운데 업무가 멈춘 것 ${n(contexa.falseBlock.hits)}회, 추가 인증을 거쳐 처리된 것 ${n(contexa.friction.hits)}회`);
await shots('adopt-steps');
await open('/adopt?step=on');
check('adopt', 'old ?step=on opens shadow mode', await page.getByRole('tab', { name: '관찰 모드' }).getAttribute('aria-selected'), 'true');
const record = await text(page.getByRole('region', { name: '이 데모를 관찰 모드로 두었다면' }));
has('adopt', 'shadow: decisions', record, `${n(stats.engineDecisions)}건`);
for (const [label, action] of [['차단', 'BLOCK'], ['추가 인증', 'CHALLENGE'], ['검토 보류', 'ESCALATE']]) {
  has('adopt', `shadow: ${label}`, record, `${label} ${n(stats.engineActions[action])}건`);
}
has('adopt', 'mode now', await text(page.locator('main')), `이 데모의 지금 모드 · ${settings.engine.effectiveMode}`);
await shots('adopt-shadow');
await open('/adopt?tab=retention');
const retention = await page.getByRole('table', { name: '보관 · 감사 기본값' }).locator('tbody tr').allInnerTexts();
has('adopt', 'sample: this demo', retention[0].replace(/\s+/g, ' '), `요청의 ${n(settings.sealedEvidence.samplePercent)}%`);
has('adopt', 'clean: this demo', retention[3].replace(/\s+/g, ' '), `${n(settings.sealedEvidence.cleanPeriodDays)}일`);
has('adopt', 'behaviour: this demo', retention[5].replace(/\s+/g, ' '), `${n(settings.retention.behaviorDays)}일`);
has('adopt', 'original text kept', await text(page.locator('main')), `이 데모 포털이 ${n(settings.retention.promptOriginalDays)}일 보관합니다`);
await shots('adopt-retention');

// ── 3. The tour plays files the web serves; the privacy page names the cookies the portal sets ──────────────────────
const manifest = await (await page.request.get(`${web}/guides/guides.json`)).json();
await open('/tour');
check('tour', 'videos listed', await page.getByRole('region', { name: '영상 목록' }).getByRole('link').count(), Object.keys(manifest).length);
for (const [id, video] of Object.entries(manifest)) {
  const files = [video.file, ...Object.values(video.captions ?? {}), ...Object.values(video.captionsNarrow ?? {})];
  for (const file of files) {
    check('tour', `${id}: ${file} served`, (await page.request.get(`${web}/guides/${file}`)).status(), 200);
  }
}
check('tour', 'no autoplay', await page.locator('video').getAttribute('autoplay'), null);
await shots('tour');
const visitor = await page.request.get(`${api}/api/visitor`);
const cookieNames = visitor.headersArray().filter((header) => header.name.toLowerCase() === 'set-cookie').map((header) => header.value.split('=')[0]);
await open('/privacy');
const named = await page.getByRole('table', { name: '쿠키' }).locator('tbody tr code').allInnerTexts();
check('privacy', 'cookies named = cookies set', [...named].sort(), [...cookieNames].sort());
await shots('privacy');

// ── 4. The glossary and the old addresses ───────────────────────────────────────────────────────────────────────
await open('/glossary');
has('glossary', 'term count', await text(page.locator('main')), '용어 71개');
await open('/?modal=glossary&term=usual');
await page.waitForURL(/\/glossary\?term=baseline/);
has('glossary', 'old link → baseline', await text(page.getByRole('complementary', { name: '행위 기준선' })), '주체의 학습된 정상 행위 범위');
await shots('glossary-term');
for (const [from, to] of [['/stats', '/metrics'], ['/videos', '/tour'], ['/summary/next', '/adopt'], ['/try/summary/end', '/adopt']]) {
  await page.goto(`${web}${from}`);
  await page.locator('h1').first().waitFor();
  check('old addresses', `${from} → ${to}`, new URL(page.url()).pathname, to);
}
check('pages', 'no page error', errors, []);

report.finishedAt = new Date().toISOString();
report.summary = { checks: report.checks.length, same: report.checks.filter((found) => found.same).length, problems: report.problems.length };
writeFileSync(join(out, 'real-record-report.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report.summary));
for (const problem of report.problems) {
  console.log('PROBLEM', problem);
}
await browser.close();
