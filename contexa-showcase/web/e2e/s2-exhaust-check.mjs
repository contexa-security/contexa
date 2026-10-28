// docs/agent Agent중심-화면 S2 real-server check (AC-5 (2), G-5): with the day's allotment spent the portal starts
// nothing: an agent visitor who presses "send" is led to the stored runs, the start is refused with 503 ALLOTMENT, and no
// model is called. The portal must run with a tiny monthly budget (SHOWCASE_LIVE_MONTHLY_BUDGET=0.01 for
// debug-restart-portal.sh) so the day's allotment is already spent. READ-ONLY apart from the refused start: the caller
// compares the database (run rows, ledger rows) before and after.
// Usage (web folder): node e2e/s2-exhaust-check.mjs <outDir> [--base http://127.0.0.1:19180]
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s2-exhaust-check.mjs <outDir> [--base <url>]');
  process.exit(2);
}
const baseAt = args.indexOf('--base');
const base = baseAt >= 0 ? args[baseAt + 1] : 'http://127.0.0.1:19180';
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [], startStatuses: [] };
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
  page.on('response', (response) => {
    if (response.url() === `${base}/api/live/runs` && response.request().method() === 'POST') {
      report.startStatuses.push(response.status());
    }
  });
  const json = async (url) => (await page.request.get(base + url)).json();
  const shot = (name) => page.screenshot({ path: path.join(out, `${name}.png`), fullPage: true });

  const config = await json('/api/live/config');
  check('the day is spent: the config says paused', config.paused === true, `paused ${config.paused}`);

  // an agent visitor presses send
  await page.goto(`${base}/agent/request?lng=ko`, { waitUntil: 'networkidle' });
  await page.getByLabel('보내는 쪽: 위임 에이전트').first().waitFor({ timeout: 15000 });
  await page.locator('label', { hasText: '멈춘다' }).first().click();
  await page.getByRole('button', { name: '에이전트에게 맡기기' }).click();
  await page.waitForResponse((response) => response.url() === `${base}/api/live/runs`, { timeout: 30000 });
  check('the start is refused with 503 (the allotment)', report.startStatuses.at(-1) === 503, JSON.stringify(report.startStatuses));
  const alert = page.getByRole('alert');
  await alert.first().waitFor({ timeout: 15000 });
  await shot('6-1-paused');
  check('the screen leads on to a stored real run', (await page.getByRole('link', { name: /저장된|기록/ }).count()) >= 1);

  // the stored runs still open, read from files and the database, no model
  await page.goto(`${base}/agent/result?lng=ko`, { waitUntil: 'networkidle' });
  await page.getByText(/실제 실행 · 저장된 기록/).first().waitFor({ timeout: 15000 });
  check('6-7 shows the stored real run with its badge', true);
  await shot('6-7-stored');
  await page.goto(`${base}/agent/reason?lng=ko`, { waitUntil: 'networkidle' });
  check('6-3 opens with the stored run', (await page.getByRole('region', { name: '맡긴 일과 실제 요청을 나란히' }).count()) === 1);
  await page.goto(`${base}/lab/agent?lng=ko`, { waitUntil: 'networkidle' });
  await page.getByRole('radiogroup', { name: '사례' }).waitFor({ timeout: 15000 });
  check('the agent menu still answers from stored runs', (await page.getByRole('region', { name: '고른 조합의 저장된 결과' }).count()) === 1);
  await shot('lab-agent');

  const after = await json('/api/live/config');
  check('nothing was counted for the refused send', after.remainingToday === config.remainingToday
    && after.remainingAgentToday === config.remainingAgentToday);
  check('no script error on the screens', errors.length === 0, errors.slice(0, 2).join(' | '));
} finally {
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(report.failures.length === 0 ? 'ALL PASS' : `FAILED: ${report.failures.join('; ')}`);
process.exit(report.failures.length === 0 ? 0 : 1);
