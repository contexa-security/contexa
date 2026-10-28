// docs/agent Agent중심-화면 AC-6 real-server check (G-12 (1)(2), AC-6 (2)): the day's share of live agent runs is spent but the day's
// allotment is not (the portal runs with a monthly budget whose rest of the day is less than one agent run, see
// debug-restart-portal.sh SHOWCASE_LIVE_MONTHLY_BUDGET). Then: (1) the config says live runs are not paused and the share is 0;
// (2) every agent start (the open case, the editable case, the live burst) is refused with 503 ALLOTMENT and takes no
// points and no agent run; (3) a person's run still starts (202) and is then ended by its visitor; (4) in a real browser
// 6-1 presses send and is led to the stored runs, and 6-6 says the share is spent, leads to the stored measurements and
// keeps its send button closed. The caller compares the database before and after the refused starts.
// Usage (web folder): node e2e/s3-ration-check.mjs <outDir> [--base http://127.0.0.1:19180]
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s3-ration-check.mjs <outDir> [--base <url>]');
  process.exit(2);
}
const baseAt = args.indexOf('--base');
const base = baseAt >= 0 ? args[baseAt + 1] : 'http://127.0.0.1:19180';
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [], starts: [] };
function check(name, ok, detail = '') {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

const browser = await chromium.launch();
try {
  const context = await browser.newContext({ locale: 'ko-KR', viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  await page.goto(`${base}/?lng=ko`, { waitUntil: 'networkidle' });
  const xsrf = (await context.storageState()).cookies.find((cookie) => cookie.name === 'XSRF-TOKEN')?.value ?? '';
  const headers = { 'X-XSRF-TOKEN': xsrf, 'Content-Type': 'application/json' };
  const json = async (url) => (await page.request.get(base + url)).json();
  const post = async (data) => {
    const response = await page.request.post(`${base}/api/live/runs`, { data, headers });
    let body = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    report.starts.push({ scenario: data.scenario, status: response.status(), reason: body?.reason ?? null });
    return { status: response.status(), body };
  };
  const shot = (name) => page.screenshot({ path: path.join(out, `${name}.png`), fullPage: true });

  const config = await json('/api/live/config');
  check('live runs are not paused: the day is not spent', config.paused === false, `paused ${config.paused}`);
  check('the day\'s share of live agent runs is spent', config.liveTicketsLeft === 0, `tickets ${config.liveTicketsLeft}`);

  // (2) every agent start is refused with 503 ALLOTMENT, and counts nothing
  for (const [name, data] of [
    ['the open case T5', { scenario: 'T5', turnstileToken: null }],
    ['the editable case ED1', { scenario: 'ED1', turnstileToken: null, delegation: { quantity: 400 } }],
    ['the live burst', { scenario: 'M41A', turnstileToken: null, copies: 5 }],
  ]) {
    const answer = await post(data);
    check(`${name}: the start is refused with 503 ALLOTMENT`, answer.status === 503 && answer.body?.reason === 'ALLOTMENT',
      JSON.stringify(report.starts.at(-1)));
  }
  const afterRefusals = await json('/api/live/config');
  check('the refused starts took no points and no agent run', afterRefusals.remainingToday === config.remainingToday
    && afterRefusals.remainingAgentToday === config.remainingAgentToday,
  `${config.remainingToday}/${config.remainingAgentToday} -> ${afterRefusals.remainingToday}/${afterRefusals.remainingAgentToday}`);

  // (3) a person's run is not rationed
  const person = config.scenarios.find((scenario) => scenario.subject === 'PERSON');
  const started = await post({ scenario: person.key, turnstileToken: null });
  check(`a person's run (${person.key}) still starts (202)`, started.status === 202, JSON.stringify(report.starts.at(-1)));
  if (started.status === 202) {
    const afterPerson = await json('/api/live/config');
    check('it costs a person\'s 1 point', config.remainingToday - afterPerson.remainingToday === 1,
      `${config.remainingToday} -> ${afterPerson.remainingToday}`);
    await page.request.post(`${base}/api/live/runs/current/cancel`, { headers });
  }

  // (4) the screens, in a real browser (the visitor still has a person's run to end: it was cancelled above)
  await page.goto(`${base}/agent/request?lng=ko`, { waitUntil: 'networkidle' });
  await page.getByText('오늘 보낼 수 있는 진짜 실행은 모두 나갔습니다.').waitFor({ timeout: 15000 });
  check('6-1 says no live run is left today and leads to the stored runs', (await page.getByRole('link', { name: '저장된 실행 보기' }).count()) === 1);
  await page.getByLabel('보내는 쪽: 위임 에이전트').first().waitFor({ timeout: 15000 }).catch(() => undefined);
  await shot('6-1-no-share');
  await page.goto(`${base}/agent/burst?lng=ko`, { waitUntil: 'networkidle' });
  await page.getByText('오늘 실시간으로 보낼 수 있는 몫을 모두 썼습니다.').waitFor({ timeout: 15000 });
  check('6-6 says the share is spent and leads to the stored measurements', (await page.getByRole('link', { name: '저장된 측정 보기' }).count()) === 1);
  check('6-6 keeps its send button closed', await page.getByRole('button', { name: '10건 실제로 보내기' }).isDisabled());
  check('the stored measurements are still on 6-6', (await page.getByRole('region', { name: /같은 목록 요청 60건/ }).count()) === 1);
  await shot('6-6-no-share');
  await page.goto(`${base}/lab/agent?lng=ko`, { waitUntil: 'networkidle' });
  await page.getByRole('radiogroup', { name: '사례' }).waitFor({ timeout: 15000 });
  check('the agent menu still answers from stored runs', (await page.getByRole('region', { name: '고른 조합의 저장된 결과' }).count()) === 1);
  check('no script error on the screens', errors.length === 0, errors.slice(0, 2).join(' | '));
} finally {
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(report.failures.length === 0 ? 'ALL PASS' : `FAILED: ${report.failures.join('; ')}`);
process.exit(report.failures.length === 0 ? 0 : 1);
