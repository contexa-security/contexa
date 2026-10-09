// S4 check on the real stack (C-2, C-4, C-9, C-16): act 2 in Korean and English. Try 2 sends one live run per
// language through the visitor's own gate (answering the identity check in place when Contexa asks for one), then the
// published rules with their original, the identity check step, the follow-up map and the act-end screen. Every
// screen is captured at 390, 768, 1024 and 1440 px and checked like act 1; the values the screens read are kept for
// comparison with the API.
// Usage: node e2e/s4-act2.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { capture } from './screenCheck.mjs';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:5180';
const DICTIONARIES = {
  ko: JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8')),
  en: JSON.parse(readFileSync('src/i18n/en.json', 'utf-8')),
};
mkdirSync(out, { recursive: true });

const api = (page, path) => page.evaluate((p) => fetch(p).then((r) => (r.ok ? r.json() : null)), path);
const format = (template, values) =>
  template.replace(/\{\{(\w+)\}\}/g, (_, key) => String(values[key] ?? ''));

const browser = await chromium.launch();
const report = [];
const values = [];
for (const language of ['ko', 'en']) {
  const m = DICTIONARIES[language];
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    locale: language,
    reducedMotion: 'reduce',
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 300)));

  for (const step of ['scene', 'compare']) {
    await page.goto(`${base}/try/owner/${step}?lng=${language}`, { waitUntil: 'networkidle' });
    await capture(page, out, language, `e2-${step}`, report);
  }
  const before = await api(page, '/api/live/before/A3T?step=1');
  values.push({
    language,
    screen: 'compare',
    departureCount: before?.comparison?.departureCount,
    companyAdverseCount: before?.comparison?.companyAdverseCount,
    heading: await page.locator('h1').innerText(),
  });

  await page.goto(`${base}/try/owner/predict?lng=${language}`, { waitUntil: 'networkidle' });
  await capture(page, out, language, 'e2-predict', report);
  await page.getByText(m['e1.predict.ALLOW'], { exact: true }).first().click();
  await page
    .locator('fieldset', { hasText: m['e2.predict.numberRule'] })
    .getByText(m['e2.predict.numberRule.STOP'], { exact: true })
    .click();
  const options = await api(page, '/api/lab/options');
  const items = options.cases.find((c) => c.key === 'A3T').requests[0].items;
  await page
    .getByRole('button', {
      name: format(m['e1.predict.send'], {
        items: items.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US'),
      }),
    })
    .click();
  await page.waitForURL(/\/try\/owner\/run/, { timeout: 30_000 });

  // The real employee answers the check in place when Contexa asks for one; the code is in their own demo inbox.
  const deadline = Date.now() + 180_000;
  let answered = false;
  while (Date.now() < deadline) {
    if (await page.getByRole('link', { name: m['e1.next.result'] }).count()) {
      const live = await api(page, '/api/live/runs/current');
      if (live?.challenge && !answered && live.challenge.stage !== 'DONE') {
        // fall through to answer
      } else {
        break;
      }
    }
    const request = page.getByRole('button', { name: m['try.challenge.requestCode'] });
    if (await request.count()) {
      await request.click();
    }
    const use = page.getByRole('button', { name: m['try.challenge.useCode'] });
    if (await use.count()) {
      await use.click();
      answered = true;
    }
    await page.waitForTimeout(1000);
  }
  await capture(page, out, language, 'e2-run', report);

  await page.goto(`${base}/try/owner/result?lng=${language}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);
  const live = await api(page, '/api/live/runs/current');
  const score = live?.runId ? await api(page, `/api/runs/${live.runId}/score`) : null;
  values.push({
    language,
    screen: 'result',
    runId: live?.runId,
    challenge: live?.challenge?.stage ?? null,
    business: score?.business,
    correct: score?.correct,
    heading: await page.locator('h1').innerText(),
    rows: await page.locator('table tbody tr').allInnerTexts(),
  });
  await capture(page, out, language, 'e2-result', report);

  await page.goto(`${base}/try/owner/reason?lng=${language}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);
  await capture(page, out, language, 'e2-reason', report);

  await page.goto(`${base}/intro/how/rules?lng=${language}`, { waitUntil: 'networkidle' });
  await capture(page, out, language, 'g-rules', report);
  const original = page.getByRole('button', { name: /원문|lines of the rules/ });
  if (await original.count()) {
    await original.click();
    await page.waitForTimeout(1500);
    await page.screenshot({ path: join(out, `g-rules-original-${language}-1440.png`), fullPage: false });
    values.push({
      language,
      screen: 'g-rules-original',
      lines: await page.locator('dialog ol li').count(),
      plainNotes: await page.locator('dialog ol li[data-plain]').count(),
    });
    await page.keyboard.press('Escape');
  }

  await page.goto(`${base}/try/owner/after?lng=${language}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);
  await capture(page, out, language, 'e2-check', report);
  values.push({ language, screen: 'check', heading: await page.locator('h1').innerText() });

  await page.goto(`${base}/try/follow?lng=${language}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);
  await capture(page, out, language, 'follow', report);
  const stats = await api(page, '/api/stats');
  values.push({ language, screen: 'follow', engineActions: stats?.engineActions, releases: stats?.releases });

  await page.getByRole('link', { name: m['e2.next.end'] }).click();
  await page.waitForURL(/\/try\/follow\/end/, { timeout: 30_000 });
  await page.waitForTimeout(1500);
  await capture(page, out, language, 'follow-end', report);
  values.push({
    language,
    screen: 'follow-end',
    badge: await page
      .getByRole('button', { name: /확인한 차이|Differences seen/ })
      .first()
      .innerText(),
  });
  values.push({ language, screen: 'errors', errors });
  await context.close();
}
await browser.close();
writeFileSync(join(out, 's4-report.json'), JSON.stringify({ report, values }, null, 1));
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
console.log(JSON.stringify(values, null, 1).slice(0, 6000));
