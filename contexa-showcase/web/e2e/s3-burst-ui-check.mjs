// docs/agent Agent중심-화면 AS-13 real-server check in a real browser (G-5): 6-6 with the visitor's own live burst. The visitor opens
// 6-6, sees the numbers up to ten with ten chosen and what a burst costs, picks five, sends it, stays on 6-6 while it
// runs (the button says it is sending, the screen says it runs), and when the run ends reads the counts of their own
// burst in the rows of the stored measurements; every value shown is compared with the portal's own run view
// (`/api/runs/{id}/agent`.burst). Screenshots at 1440 and 390 px, Korean and English.
// Cost: one live burst. Usage (web folder): node e2e/s3-burst-ui-check.mjs <outDir> [--base http://127.0.0.1:19180] [--copies 5]
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s3-burst-ui-check.mjs <outDir> [--base <url>] [--copies <n>]');
  process.exit(2);
}
const option = (name, fallback) => {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : fallback;
};
const base = option('--base', 'http://127.0.0.1:19180');
const copies = Number(option('--copies', '5'));
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [], run: null };
function check(name, ok, detail = '') {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

const ROW_WORDS = ['보낸 요청', '전달', '거부', '분석 중이라 거부', '자체 판정이 있는 요청', '모델 호출', '처음 멈춘 뒤에 전달된 요청', '처음 멈춘 요청'];
const SUMMARY_KEYS = ['requests', 'delivered', 'refused', 'busy', 'withVerdict', 'modelCalls', 'deliveredAfterFirstStop'];

const browser = await chromium.launch();
try {
  const context = await browser.newContext({ locale: 'ko-KR', viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  const json = async (url) => (await page.request.get(base + url)).json();
  const shot = (name) => page.screenshot({ path: path.join(out, `${name}.png`), fullPage: true });

  await page.goto(`${base}/agent/burst?lng=ko`, { waitUntil: 'networkidle' });
  const before = await json('/api/live/config');
  const group = page.getByRole('radiogroup', { name: '한꺼번에 보낼 요청 수' });
  await group.waitFor({ timeout: 20000 });
  const values = await group.getByRole('radio').evaluateAll((nodes) => nodes.map((node) => node.value));
  check('6-6 offers 1, 3, 5 and 10 requests', JSON.stringify(values) === '["1","3","5","10"]', JSON.stringify(values));
  check('ten is chosen at first', await group.getByRole('radio', { name: '10건' }).isChecked());
  check('the screen says what a burst costs', (await page.getByText(`한 번에 ${before.burst.points}점을 쓰고`).count()) === 1);
  check('the measured bursts are still on the screen beneath it', (await page.getByRole('region', { name: /같은 목록 요청 60건/ }).count()) === 1);
  await shot('6-6-before-1440');

  await group.getByText(`${copies}건`, { exact: true }).click();
  const send = page.getByRole('button', { name: `${copies}건 실제로 보내기` });
  await send.waitFor({ timeout: 10000 });
  await send.click();
  await page.getByRole('button', { name: '보내는 중' }).waitFor({ timeout: 15000 });
  check('the button says it is sending while the run goes', true);
  // the note shows once the portal has answered the start (the request is still on its way when the button first says so)
  const note = await page.getByText(/실행 중입니다\. 열 건이면 3~4분쯤/).first().waitFor({ timeout: 30000 }).then(() => true, () => false);
  check('the screen says the run goes and how long it takes', note);
  check('the visitor stays on 6-6', page.url().includes('/agent/burst'), page.url());
  await shot('6-6-running-1440');
  const mid = await json('/api/live/config');
  check(`a burst costs ${before.burst.points} points and 1 agent run`, before.remainingToday - mid.remainingToday === before.burst.points
    && before.remainingAgentToday - mid.remainingAgentToday === 1, `${before.remainingToday}/${before.remainingAgentToday} -> ${mid.remainingToday}/${mid.remainingAgentToday}`);

  const own = page.getByRole('region', { name: '내가 보낸 요청의 결과' });
  await own.waitFor({ timeout: 8 * 60_000 });
  const live = await json('/api/live/runs/current');
  report.run = { liveRunId: live.liveRunId, status: live.status, runId: live.runId };
  check('the run ended COMPLETED', live.status === 'COMPLETED', JSON.stringify(report.run));
  const runView = await json(`/api/runs/${live.runId}/agent`);
  const rows = await own.getByRole('row').evaluateAll((nodes) => nodes.map((node) => [...node.children].map((cell) => cell.textContent?.trim() ?? '')));
  const shown = Object.fromEntries(rows.filter((row) => row.length === 2 && row[0]).map((row) => [row[0], row[1]]));
  check('the result table has every row of the stored measurements', ROW_WORDS.every((word) => word in shown), Object.keys(shown).join(' | '));
  const expected = SUMMARY_KEYS.map((key) => String(runView.burst[key]));
  const actual = ROW_WORDS.slice(0, 7).map((word) => (shown[word] ?? '').replace(/,/g, ''));
  check('every count on the screen equals the portal\'s own count of the run', JSON.stringify(expected) === JSON.stringify(actual),
    JSON.stringify({ expected, actual }));
  check('at least the burst requests were sent', runView.burst.requests >= copies, `${runView.burst.requests}`);
  check('no request was refused as busy, nothing leaked after the first stop', runView.burst.busy === 0 && runView.burst.deliveredAfterFirstStop === 0);
  const end = await json('/api/live/config');
  check(`the completed burst stays paid: ${before.burst.points} points and 1 agent run`, before.remainingToday - end.remainingToday === before.burst.points
    && before.remainingAgentToday - end.remainingAgentToday === 1);
  check('the button is ready to send again', await page.getByRole('button', { name: `${copies}건 실제로 보내기` }).isEnabled());
  await shot('6-6-result-1440');

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${base}/agent/burst?lng=ko`, { waitUntil: 'networkidle' });
  await page.getByRole('region', { name: '내가 보낸 요청의 결과' }).waitFor({ timeout: 20000 });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check('at 390 px the page does not scroll sideways', overflow <= 0, `${overflow}px`);
  await shot('6-6-result-390');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(`${base}/agent/burst?lng=en`, { waitUntil: 'networkidle' });
  await page.getByRole('region', { name: 'The result of the requests you sent' }).waitFor({ timeout: 20000 });
  check('the English screen shows the live part and the result in English', (await page.getByRole('heading', { name: 'Send a burst yourself' }).count()) === 1);
  await shot('6-6-result-en-1440');
  check('no script error on the screens', errors.length === 0, errors.slice(0, 2).join(' | '));
} finally {
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(`${report.checks.length - report.failures.length}/${report.checks.length} passed`);
console.log(report.failures.length === 0 ? 'ALL PASS' : `FAILED: ${report.failures.join('; ')}`);
process.exit(report.failures.length === 0 ? 0 : 1);
