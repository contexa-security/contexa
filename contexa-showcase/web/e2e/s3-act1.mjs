// S3 check on the real stack (C-2, C-4, C-6, C-9, C-12, C-16): the first screen and try 1 in its seven steps and the
// act-end screen, in Korean and English. One live run per language goes through the visitor's own gate; every step is
// captured at 390, 768, 1024 and 1440 px and checked for horizontal overflow, single-letter wrapping and serious or
// critical axe violations, and the values on screen are compared with the API the screen reads.
// Usage: node e2e/s3-act1.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { capture } from './screenCheck.mjs';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:5180';
const STEPS = ['scene', 'compare', 'predict', 'run', 'result', 'reason', 'after'];
const COPY = {
  ko: {
    next: '다음 · 결과 보기',
    badge: '확인한 차이 4/6',
    send: /보내기 · /,
    call: '본인 확인',
    existing: '일부만 막는다',
    end: '다음 · 막 1 정리',
  },
  en: {
    next: 'Next · See the result',
    badge: 'Differences seen 4/6',
    send: /Send · /,
    call: 'Identity check',
    existing: 'Only some stop it',
    end: 'Next · Act 1 wrap-up',
  },
};
mkdirSync(out, { recursive: true });

const api = (page, path) => page.evaluate((p) => fetch(p).then((r) => (r.ok ? r.json() : null)), path);

const browser = await chromium.launch();
const report = [];
const values = [];
for (const language of ['ko', 'en']) {
  const copy = COPY[language];
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    locale: language,
    reducedMotion: 'reduce',
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 300)));

  await page.goto(`${base}/?lng=${language}`, { waitUntil: 'networkidle' });
  await page.locator('[data-side="attacker"]').waitFor();
  const hook = await api(page, '/api/hook');
  const contexaRow = await page.locator('[data-side="attacker"] [data-contexa]').innerText();
  values.push({
    language,
    screen: 'hook',
    attackerRun: hook?.attacker.runId,
    contexaRow,
    attackerItems: hook?.attacker.result.layers.find((l) => l.control === 'D')?.evidence.deliveredItems,
    measured: hook?.attacker.measurement,
  });
  await capture(page, out, language, 'hook', report);

  for (const step of STEPS) {
    if (step === 'run' || step === 'result' || step === 'reason' || step === 'after') {
      // Reached by sending and by the steps' own links, below.
    }
    if (step === 'scene' || step === 'compare') {
      await page.goto(`${base}/try/attacker/${step}?lng=${language}`, { waitUntil: 'networkidle' });
      await capture(page, out, language, `e1-${step}`, report);
    }
    if (step === 'predict') {
      await page.goto(`${base}/try/attacker/predict?lng=${language}`, { waitUntil: 'networkidle' });
      await capture(page, out, language, 'e1-predict', report);
      await page.getByText(copy.call, { exact: true }).first().click();
      await page.getByText(copy.existing, { exact: true }).click();
      await page.getByRole('button', { name: copy.send }).click();
      await page.waitForURL(/\/try\/attacker\/run/, { timeout: 30_000 });
    }
    if (step === 'run') {
      const started = Date.now();
      // S2-10: while the decision is still coming, the analysis answer carries the server's "about s seconds".
      let wait = null;
      for (let i = 0; i < 20 && wait === null; i += 1) {
        const analysis = await api(page, '/api/live/runs/current/analysis?step=1');
        wait = analysis?.decisionWait ?? (analysis?.decision ? 'decided' : null);
        if (wait === null) await page.waitForTimeout(500);
      }
      values.push({ language, screen: 'run-wait', decisionWait: wait });
      await page.getByRole('link', { name: copy.next }).waitFor({ timeout: 180_000 });
      values.push({
        language,
        screen: 'run',
        secondsToAllAnswers: Math.round((Date.now() - started) / 1000),
      });
      await capture(page, out, language, 'e1-run', report);
    }
    if (step === 'result') {
      await page.goto(`${base}/try/attacker/result?lng=${language}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(1500);
      const live = await api(page, '/api/live/runs/current');
      const score = live?.runId ? await api(page, `/api/runs/${live.runId}/score`) : null;
      const rows = await page.locator('table tbody tr').allInnerTexts();
      values.push({
        language,
        screen: 'result',
        runId: live?.runId,
        business: score?.business,
        correct: score?.correct,
        rows,
      });
      await capture(page, out, language, 'e1-result', report);
    }
    if (step === 'reason' || step === 'after') {
      await page.goto(`${base}/try/attacker/${step}?lng=${language}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(1500);
      await capture(page, out, language, `e1-${step}`, report);
    }
    if (step === 'after') {
      // The act-end card is a screen of its own after the follow-up (D-41), reached by its next button.
      await page.getByRole('link', { name: copy.end }).click();
      await page.waitForURL(/\/try\/attacker\/end/, { timeout: 30_000 });
      await page.waitForTimeout(1500);
      await capture(page, out, language, 'e1-end', report);
    }
  }
  const badge = await page.getByRole('button', { name: copy.badge }).count();
  const live = await api(page, '/api/live/runs/current');
  values.push({
    language,
    screen: 'after',
    badgeFour: badge > 0,
    challenge: live?.challenge?.stage,
    status: live?.status,
  });
  values.push({ language, screen: 'errors', errors });
  await context.close();
}
await browser.close();
writeFileSync(join(out, 's3-report.json'), JSON.stringify({ report, values }, null, 1));
for (const row of report.filter((entry) => entry.width === 1440)) {
  console.log(
    `${row.language} ${row.name}: main buttons ${row.limits?.primaries}, numbers ${row.limits?.numbers}, english ${JSON.stringify(row.language === 'ko' ? row.limits?.english : [])}`,
  );
}
for (const row of report) {
  if (row.overflow || row.singleLetter.length || row.serious.length) {
    console.log(
      `${row.language} ${row.name} ${row.width}: overflow ${row.overflow}, single-letter ${JSON.stringify(row.singleLetter)}, axe ${JSON.stringify(row.serious)}`,
    );
  }
}
console.log(`screens checked ${report.length}`);
console.log(JSON.stringify(values, null, 1).slice(0, 4000));
