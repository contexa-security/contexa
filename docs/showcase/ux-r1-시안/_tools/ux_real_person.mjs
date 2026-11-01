// UX-R1 I-3 real-server check (구현계획서 DEC-9, 완료판정기준 UC-10): one visitor sends S13, S13T and S16 through the
// new screens served by the portal, walks any step-up or release the run asks for, opens the result, and the screen's
// numbers are compared with the portal's HTTP answers and the portal database's rows. Real engine runs (paid): record
// the batch in UX-R1-비용장부.md before and after.
//
//   node ux_real_person.mjs --base http://127.0.0.1:19180 --out <dir> [--cases S13,S13T,S16]
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
const cases = arg('cases', 'S13,S13T,S16').split(',');
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

const PREDICT = { S13: /차단 · 추가 인증/, S13T: /^허용/, S16: /차단 · 추가 인증/ };
const report = { base, startedAt: new Date().toISOString(), runs: [], compare: null, progress: null, problems: [] };

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR' });
const page = await context.newPage();
page.setDefaultTimeout(20000);

async function json(path) {
  const response = await page.request.get(`${base}${path}`);
  return response.ok() ? response.json() : { status: response.status() };
}

try {
  for (const key of cases) {
    const entry = { key, steps: [] };
    report.runs.push(entry);
    await page.goto(`${base}/simulate/person/${key}/review?lng=ko`, { waitUntil: 'networkidle' });
    await page.getByRole('radio', { name: PREDICT[key] }).click();
    const run = page.getByRole('button', { name: '요청 실행' });
    await page.waitForFunction(() => !document.querySelector('button[aria-busy="true"]'));
    await run.click();
    await page.waitForURL(`**/simulate/person/${key}/live`, { timeout: 60000 });
    entry.steps.push(`live opened ${new Date().toISOString()}`);
    const deadline = Date.now() + 240000;
    let done = false;
    while (Date.now() < deadline) {
      const result = page.getByRole('link', { name: '결과 · 판정 근거' });
      if (await result.count()) {
        done = true;
        break;
      }
      // The step-up and the release, walked as the account owner or the insider would.
      for (const [name, step] of [
        ['코드 받기', 'step-up: code requested'],
        ['이 코드로 확인', 'step-up: code used'],
        ['본인 확인 시작', 'release: identity check started'],
        ['해제 요청 보내기', 'release: request sent'],
        ['보안 담당자로 승인', 'release: approved'],
      ]) {
        const button = page.getByRole('button', { name, exact: true });
        if ((await button.count()) && (await button.first().isEnabled())) {
          await button.first().click();
          entry.steps.push(step);
          await page.waitForTimeout(800);
        }
      }
      const failed = page.getByText('판정을 끝내지 못했습니다', { exact: false });
      if (await failed.count()) {
        entry.steps.push('run ended without a decision');
        break;
      }
      await page.waitForTimeout(1000);
    }
    await page.screenshot({ path: join(out, `${key}-live-1440.png`), fullPage: true });
    if (!done) {
      report.problems.push(`${key}: the result did not open within 240 s`);
      continue;
    }
    const href = await page.getByRole('link', { name: '결과 · 판정 근거' }).getAttribute('href');
    const runId = new URL(href, base).searchParams.get('run');
    entry.runId = runId;
    entry.liveRows = await page
      .getByRole('table', { name: '5개 보안 통제의 응답' })
      .first()
      .locator('tbody tr')
      .allInnerTexts();
    await page.getByRole('link', { name: '결과 · 판정 근거' }).click();
    await page.waitForURL(`**/simulate/person/${key}/result**`);
    const heading = page.getByRole('heading', { level: 1 });
    await heading.waitFor();
    await page.waitForTimeout(1500);
    entry.conclusion = (await heading.innerText()).trim();
    entry.exportsRows = await page
      .getByRole('region', { name: '반출 건수 비교' })
      // The bars only: the stored responses folded under them are a list of their own (UC-5, DEC-82).
      .locator('ul')
      .first()
      .locator(':scope > li:not([aria-hidden="true"])')
      .allInnerTexts();
    entry.decisionSide = await page.locator('dl').first().innerText();
    await page.screenshot({ path: join(out, `${key}-result-1440.png`), fullPage: true });
    await page.setViewportSize({ width: 390, height: 900 });
    await page.screenshot({ path: join(out, `${key}-result-390.png`), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 900 });

    // HTTP: the server's score and the step's stored result
    const score = await json(`/api/runs/${runId}/score`);
    const step = await json(`/api/runs/${runId}/steps/1/result`);
    const anatomy = await json(`/api/runs/${runId}/steps/1/anatomy`);
    entry.http = {
      business: score.business,
      finalAction: score.verdicts?.[0]?.score?.finalAction ?? null,
      applied: score.verdicts?.[0]?.score?.applied ?? null,
      delivered: Object.fromEntries((step.layers ?? []).map((layer) => [layer.control, layer.evidence.deliveredItems])),
      responseMs: Object.fromEntries((step.layers ?? []).map((layer) => [layer.control, layer.evidence.responseMs])),
      totalAnalysisMs: anatomy.interpretation?.timings?.totalAnalysisMs ?? null,
    };
    // DB: the run, every control's answer to step 1 and Contexa's decision
    entry.db = {
      run: db(`select scenario_key, status, live_run from run where run_id = '${runId}';`)[0] ?? null,
      arms: db(`select control, http_status, outcome, delivered_items, elapsed_ms from run_arm_result where run_id = '${runId}' and step_no = 1 order by control;`),
      decision: db(`select final_action, risk_score, confidence, total_analysis_ms, applied from run_decision where run_id = '${runId}' and step_no = 1;`)[0] ?? null,
    };
    // Screen = HTTP = DB on the numbers the result shows
    const dbDelivered = Object.fromEntries(entry.db.arms.map(([control, , , items]) => [control, Number(items)]));
    for (const control of ['A', 'B', 'C1', 'C2', 'D']) {
      if (entry.http.delivered[control] !== dbDelivered[control]) {
        report.problems.push(`${key} ${control}: HTTP delivered ${entry.http.delivered[control]} ≠ DB ${dbDelivered[control]}`);
      }
    }
    if (entry.db.decision && entry.http.finalAction !== entry.db.decision[0]) {
      report.problems.push(`${key}: HTTP final action ${entry.http.finalAction} ≠ DB ${entry.db.decision[0]}`);
    }
    const exposedOnScreen = entry.exportsRows.map((row) => Number(row.split('\n')[1]?.replace(/,/g, '') ?? NaN));
    const exposedHttp = ['A', 'B', 'C1', 'C2', 'D'].map((control) => entry.http.business?.[control]?.exposedItems);
    if (JSON.stringify(exposedOnScreen) !== JSON.stringify(exposedHttp)) {
      report.problems.push(`${key}: screen exports ${JSON.stringify(exposedOnScreen)} ≠ HTTP ${JSON.stringify(exposedHttp)}`);
    }
  }

  // The comparison of the shared request and the progress, after the account takeover pair
  if (cases.includes('S13') && cases.includes('S13T')) {
    await page.goto(`${base}/simulate/person/S13/result?tab=compare&lng=ko`, { waitUntil: 'networkidle' });
    await page.getByRole('heading', { level: 1, name: '같은 요청, 다른 판정' }).waitFor();
    await page.waitForTimeout(1500);
    report.compare = {
      changedRows: await page.locator('tr[data-diff] th').allInnerTexts(),
      insight: await page.getByText('규칙 기반 통제는 두 요청을 구분하지 못했습니다').count(),
      learning: await page.getByRole('region', { name: '기준선 학습' }).innerText(),
    };
    await page.screenshot({ path: join(out, 'compare-1440.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 900 });
    await page.screenshot({ path: join(out, 'compare-390.png'), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 900 });
  }
  await page.goto(`${base}/simulate/person?lng=ko`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);
  report.progress = (await page.getByRole('region', { name: '시나리오 실행 진행' }).innerText()).split('\n')[0];
} catch (error) {
  report.problems.push(`stopped: ${error.message}`);
  await page.screenshot({ path: join(out, 'stopped.png'), fullPage: true }).catch(() => undefined);
} finally {
  report.finishedAt = new Date().toISOString();
  writeFileSync(join(out, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(JSON.stringify({ runs: report.runs.map((run) => ({ key: run.key, runId: run.runId, conclusion: run.conclusion, steps: run.steps })), compare: report.compare, progress: report.progress, problems: report.problems }, null, 2));
