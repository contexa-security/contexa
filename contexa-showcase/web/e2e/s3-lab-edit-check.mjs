// docs/agent Agent중심-화면 AS-12 / AC-4b real-server check in a real browser (G-5): the lab's delegation edit panel reads the stored
// answers of the menu after the operator's refresh of ED1. For a set of choices (every period, quantity and operations
// once, on the delegated path, and two on the other paths) the visitor picks the values, guesses "stopped" and reads
// whether the screen says the guess was right; the screen's verdict is compared with the portal's own stored answer
// (`/api/agent-menu/ED1/{path}?...`: control D's first stop), and the work line shows the delegation of that choice. READ ONLY:
// every request is a GET, so no run and no model call; the caller compares the database before and after. The link
// that starts a real run names exactly the values that differ from the case's own delegation.
// Usage (web folder): node e2e/s3-lab-edit-check.mjs <outDir> [--base http://127.0.0.1:19180]
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s3-lab-edit-check.mjs <outDir> [--base <url>]');
  process.exit(2);
}
const limitAt = args.indexOf('--limit');
// --limit n: only the first n choices (a trial of the selectors before the menu is complete)
const limit = limitAt >= 0 ? Number(args[limitAt + 1]) : 0;
const baseAt = args.indexOf('--base');
const base = baseAt >= 0 ? args[baseAt + 1] : 'http://127.0.0.1:19180';
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [], methods: {}, writes: {} };
function check(name, ok, detail = '') {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

const PERIOD = { VALID: '유효', EXPIRED: '만료', REVOKED: '취소' };
const OPERATIONS = { READ_ONLY: '읽기만', READ_EXPORT: '읽기 + 내보내기' };
const PATH_WORD = {
  OAUTH2_DELEGATED: '사람의 토큰을 받아 대신 요청',
  OAUTH2_AGENT: '자기 클라이언트 자격으로 요청',
  SESSION: '자기 계정으로 로그인해 요청',
};
const CHOICES = [
  { quantity: 40, period: 'VALID', operations: 'READ_EXPORT', path: 'OAUTH2_DELEGATED' },
  { quantity: 100, period: 'VALID', operations: 'READ_EXPORT', path: 'OAUTH2_DELEGATED' },
  { quantity: 400, period: 'VALID', operations: 'READ_EXPORT', path: 'OAUTH2_DELEGATED' },
  { quantity: 400, period: 'EXPIRED', operations: 'READ_EXPORT', path: 'OAUTH2_DELEGATED' },
  { quantity: 400, period: 'REVOKED', operations: 'READ_EXPORT', path: 'OAUTH2_DELEGATED' },
  { quantity: 400, period: 'VALID', operations: 'READ_ONLY', path: 'OAUTH2_DELEGATED' },
  { quantity: 100, period: 'EXPIRED', operations: 'READ_ONLY', path: 'OAUTH2_DELEGATED' },
  { quantity: 400, period: 'VALID', operations: 'READ_EXPORT', path: 'OAUTH2_AGENT' },
  { quantity: 400, period: 'VALID', operations: 'READ_EXPORT', path: 'SESSION' },
];

const browser = await chromium.launch();
try {
  for (const width of [1440, 390]) {
    const context = await browser.newContext({ locale: 'ko-KR', viewport: { width, height: width === 390 ? 844 : 1000 } });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(String(error)));
    page.on('request', (request) => {
      if (request.url().startsWith(base)) {
        report.methods[request.method()] = (report.methods[request.method()] ?? 0) + 1;
        if (request.method() !== 'GET') {
          report.writes[request.url().slice(base.length)] = (report.writes[request.url().slice(base.length)] ?? 0) + 1;
        }
      }
    });
    const tag = `[${width}px]`;
    await page.goto(`${base}/lab/agent?lng=ko`, { waitUntil: 'networkidle' });
    const panel = page.getByRole('region', { name: '위임장의 값을 바꿔 보기' });
    await panel.waitFor({ timeout: 20000 });
    check(`${tag} the lab shows the delegation edit panel with its lists`, (await panel.getByRole('radiogroup').count()) === 4);

    for (const choice of choices(width)) {
      const q = `quantity=${choice.quantity}&period=${choice.period}&operations=${choice.operations}`;
      const answer = await (await page.request.get(`${base}/api/agent-menu/ED1/${choice.path}?${q}`)).json();
      await panel.getByRole('radiogroup', { name: '수량 한도' }).getByText(`요청마다 ${choice.quantity}건까지`, { exact: true }).click();
      await panel.getByRole('radiogroup', { name: '위임 기간' }).getByText(PERIOD[choice.period], { exact: true }).click();
      await panel.getByRole('radiogroup', { name: '허용 작업' }).getByText(OPERATIONS[choice.operations], { exact: true }).click();
      await panel.getByRole('radiogroup').nth(3).getByText(PATH_WORD[choice.path], { exact: true }).click();
      const result = panel.getByRole('region', { name: '고른 위임장의 저장된 결과' });
      await result.getByRole('button', { name: '막았을 것이다' }).waitFor({ timeout: 15000 });
      // the work line shows the delegation of this choice (the limit the choice sets)
      const work = await result.getByText(/위임받은 일:/).innerText();
      check(`${tag} ${label(choice)}: the work line shows the delegation of the choice`, work.includes(`${choice.quantity}건`), work);
      await result.getByRole('button', { name: '막았을 것이다' }).click();
      const verdict = await result.getByRole('status').innerText();
      const stopped = answer.run?.proof?.controls?.D?.firstStopStep != null;
      check(`${tag} ${label(choice)}: the screen's verdict on the guess "stopped" equals the stored answer (${stopped ? 'stopped' : 'passed'})`,
        verdict.includes(stopped ? '예상이 맞았습니다' : '예상과 달랐습니다'), `${verdict} | firstStop ${answer.run?.proof?.controls?.D?.firstStopStep}`);
    }
    // the link that starts a real run names the values that differ from the case's own delegation (40, valid, read and export)
    const last = { quantity: 100, period: 'EXPIRED', operations: 'READ_ONLY', path: 'OAUTH2_DELEGATED' };
    await panel.getByRole('radiogroup', { name: '수량 한도' }).getByText(`요청마다 ${last.quantity}건까지`, { exact: true }).click();
    await panel.getByRole('radiogroup', { name: '위임 기간' }).getByText(PERIOD[last.period], { exact: true }).click();
    await panel.getByRole('radiogroup', { name: '허용 작업' }).getByText(OPERATIONS[last.operations], { exact: true }).click();
    const href = await panel.getByRole('link', { name: '같은 위임장으로 진짜 실행해 보기' }).getAttribute('href');
    check(`${tag} the link to a real run names the three changed values`, href === '/agent/request?case=ED1&quantity=100&period=EXPIRED&operations=READ_ONLY', href ?? '');
    await page.screenshot({ path: path.join(out, `lab-edit-${width}.png`), fullPage: true });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    check(`${tag} the page does not scroll sideways`, overflow <= 0, `${overflow}px`);
    check(`${tag} no script error on the screen`, errors.length === 0, errors.slice(0, 2).join(' | '));
    await context.close();
  }
  check('only reads: no write was made', Object.keys(report.writes).length === 0, JSON.stringify(report.writes));
} finally {
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(`${report.checks.length - report.failures.length}/${report.checks.length} passed`);
console.log(report.failures.length === 0 ? 'ALL PASS' : `FAILED: ${report.failures.join('; ')}`);
process.exit(report.failures.length === 0 ? 0 : 1);

function label(choice) {
  return `${choice.path} ${choice.quantity}/${choice.period}/${choice.operations}`;
}

/** The narrow screen checks fewer choices (the same panel, the same values). */
function choices(width) {
  const some = width === 390 ? CHOICES.filter((_, index) => [3, 5, 8].includes(index)) : CHOICES;
  return limit > 0 ? some.slice(0, limit) : some;
}
