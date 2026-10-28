// docs/agent Agent중심-화면 S2 real-server check (G-5): the agent menu (AC-4a), the replay badge (AC-5), the decision
// details' sender chip (AS-1), the burst screen (AS-10) and the benchmark's agent part (AS-11), read in a real browser on
// the running portal. READ ONLY: the script starts no run and posts nothing; it records every request method it makes so
// the caller can see that no write and no model call happened. The caller compares the database (run count, ledger rows)
// before and after.
// Usage (web folder): node e2e/s2-agent-check.mjs <outDir> [--base http://127.0.0.1:19180]
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s2-agent-check.mjs <outDir> [--base <url>]');
  process.exit(2);
}
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

const PATH_WORD = {
  OAUTH2_DELEGATED: '사람의 토큰을 받아 대신 요청',
  OAUTH2_AGENT: '자기 클라이언트 자격으로 요청',
  SESSION: '자기 계정으로 로그인해 요청',
};
const CHIP_OF_PATH = {
  OAUTH2_DELEGATED: '보내는 쪽: 위임 에이전트',
  OAUTH2_AGENT: '보내는 쪽: 단독 에이전트',
  SESSION: '보내는 쪽: 세션 에이전트',
};

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
          const where = request.url().slice(base.length);
          report.writes[where] = (report.writes[where] ?? 0) + 1;
        }
      }
    });
    const json = async (url) => (await page.request.get(base + url)).json();
    const shot = (name) => page.screenshot({ path: path.join(out, `${name}-${width}.png`), fullPage: true });
    const tag = `[${width}px]`;

    const menu = await json('/api/agent-menu');
    check(`${tag} the menu lists 5 cases on 3 paths`, menu.cases.length === 5 && menu.paths.length === 3,
      `${menu.cases.length} cases, ${menu.paths.length} paths`);
    check(`${tag} every stored item is a combination of the table`, menu.items.every(
      (item) => menu.cases.some((found) => found.key === item.caseKey) && menu.paths.includes(item.path)));
    check(`${tag} the daily job has stored answers`, menu.items.length > 0, `${menu.items.length} of 15`);

    await page.goto(`${base}/lab/agent?lng=ko`, { waitUntil: 'networkidle' });
    const caseGroup = page.getByRole('radiogroup', { name: '사례' });
    const pathGroup = page.getByRole('radiogroup', { name: '보내는 방식' });
    await caseGroup.waitFor({ timeout: 15000 });
    check(`${tag} the screen offers the cases and the three paths`, (await caseGroup.getByRole('radio').count()) === 5
      && (await pathGroup.getByRole('radio').count()) === 3);
    await shot('lab-agent');

    // every stored combination: choose it, read its badge against the API's time, guess, then read the run
    for (const item of menu.items.slice(0, width === 1440 ? menu.items.length : 3)) {
      const answer = await json(`/api/agent-menu/${item.caseKey}/${item.path}`);
      const caseTitle = menu.cases.find((found) => found.key === item.caseKey).title.ko;
      await caseGroup.locator('label', { hasText: caseTitle }).click();
      await pathGroup.locator('label', { hasText: PATH_WORD[item.path] }).click();
      const result = page.getByRole('region', { name: '고른 조합의 저장된 결과' });
      await result.getByText(answer.caseView.title.ko, { exact: true }).waitFor({ timeout: 15000 });
      const label = `${item.caseKey}/${item.path}`;
      const hours = Math.floor((Date.now() - Date.parse(answer.ranAt)) / 3_600_000);
      const expected = hours < 1 ? '방금 전' : hours < 48 ? `${hours}시간 전` : `${Math.floor(hours / 24)}일 전`;
      const badge = result.getByText(/실제 실행 · 새 모델 호출 없음/);
      check(`${tag} ${label} badge tells the age of the stored run`, (await badge.innerText()).startsWith(`${expected} 실제 실행`),
        `${await badge.innerText()} (expected ${expected})`);
      check(`${tag} ${label} stale mark equals the portal's`, (await result.getByText(/오래된 결과/).count()) === (answer.stale ? 1 : 0));
      check(`${tag} ${label} the run waits for the guess`, (await result.getByRole('heading', { name: '다섯 보안 레인' }).count()) === 0
        && (await result.getByRole('table').count()) === 0);
      const stopped = answer.run.proof?.controls?.D?.firstStopStep != null;
      await result.getByRole('button', { name: stopped ? '막았을 것이다' : '통과시켰을 것이다' }).click();
      check(`${tag} ${label} the right guess is told right`, (await result.getByText('예상이 맞았습니다.').count()) === 1);
      await result.getByRole('button', { name: stopped ? '통과시켰을 것이다' : '막았을 것이다' }).click();
      check(`${tag} ${label} the other guess is told wrong`, (await result.getByText(/예상과 달랐습니다/).count()) === 1);
      const rows = await result.locator('table tbody tr').count();
      check(`${tag} ${label} the timeline holds the run's requests`, rows > 0 && rows <= answer.run.steps.length,
        `${rows} rows, ${answer.run.steps.length} steps`);
      await shot(`menu-${item.caseKey}-${item.path}`);
    }

    // a combination with no stored answer is told so
    const stored = new Set(menu.items.map((item) => `${item.caseKey}/${item.path}`));
    const empty = menu.cases.flatMap((found) => menu.paths.map((p) => [found, p])).find(([found, p]) => !stored.has(`${found.key}/${p}`));
    if (empty) {
      await caseGroup.locator('label', { hasText: empty[0].title.ko }).click();
      await pathGroup.locator('label', { hasText: PATH_WORD[empty[1]] }).click();
      check(`${tag} a combination without an answer says so`, (await page.getByText(/아직 저장된 결과가 없습니다/).count()) >= 1);
    }

    // the decision details' sender chip, from a stored menu run of each path
    for (const item of [menu.items.find((x) => x.path === 'OAUTH2_DELEGATED'), menu.items.find((x) => x.path === 'OAUTH2_AGENT'),
      menu.items.find((x) => x.path === 'SESSION')].filter(Boolean)) {
      const answer = await json(`/api/agent-menu/${item.caseKey}/${item.path}`);
      await page.goto(`${base}/?lng=ko&modal=detail&detailRun=${answer.run.runId}&detailStep=1&detailTab=summary`, { waitUntil: 'networkidle' });
      const dialog = page.getByRole('dialog');
      await dialog.waitFor({ timeout: 15000 });
      await dialog.getByLabel(CHIP_OF_PATH[item.path]).first().waitFor({ timeout: 15000 }).catch(() => {});
      check(`${tag} the details of a ${item.path} run carry its sender chip`,
        (await dialog.getByLabel(CHIP_OF_PATH[item.path]).count()) >= 1, CHIP_OF_PATH[item.path]);
    }
    await shot('details');

    // 6-6: the stored burst measurement, read from the files; the numbers equal the portal's counts
    const burst = await json('/api/agent-snapshots/M41A-flights-on');
    await page.goto(`${base}/agent/burst?lng=ko`, { waitUntil: 'networkidle' });
    const burstText = await page.locator('main').innerText();
    check(`${tag} 6-6 shows the burst's request and model-call counts`, burstText.includes(String(burst.summary.requests))
      && burstText.includes(String(burst.summary.modelCalls)), `${burst.summary.requests} requests, ${burst.summary.modelCalls} calls`);
    check(`${tag} 6-6 says it is a stored real run`, /실제 실행 · 저장된 기록/.test(burstText));
    check(`${tag} 6-6 marks each burst as a measurement result with its requests (AC-7a)`,
      burstText.includes(`측정 결과 · 요청 ${burst.summary.requests}건`), `요청 ${burst.summary.requests}건`);
    await shot('6-6');

    // the benchmark's agent part
    const bench = await json('/api/benchmark/agent');
    await page.goto(`${base}/benchmark/agent?lng=ko`, { waitUntil: 'networkidle' });
    const benchText = await page.locator('main').innerText();
    const numbers = [bench.total.runs, bench.total.attacks, bench.total.existingMissed, bench.total.contexaStopped];
    check(`${tag} the benchmark's agent part shows the portal's counts`, numbers.every((n) => benchText.includes(String(n))),
      numbers.join(', '));
    await shot('bench-agent');
    check(`${tag} no script error on the screens`, errors.length === 0, errors.slice(0, 2).join(' | '));
    await context.close();
  }
  // The only write is the visitor's place in the journey (entering a main-flow screen saves it); nothing starts a run,
  // asks a model, predicts or assesses.
  check('nothing but reads and the journey position was sent', Object.keys(report.writes).every((where) => where === '/api/journey'),
    JSON.stringify(report.writes));
} finally {
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(report.failures.length === 0 ? 'ALL PASS' : `FAILED: ${report.failures.join('; ')}`);
process.exit(report.failures.length === 0 ? 0 : 1);
