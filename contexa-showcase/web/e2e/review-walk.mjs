// Review before the guide videos (2026-10-21) on the real stack: the main flow once as a visitor in Korean with its live
// sends (the stolen account, the owner, the owner checked on the way, the insider, the attack with one condition
// changed), one lab run of the streamed export A3S, then every visitor screen again in English. Each screen at 1440 and
// 390 px: a full-page capture, the screen checks (sideways scroll, a line ending in one letter, serious axe findings,
// phone rules), the page's visible text, page errors and failed API answers. No prompt or model accuracy is judged.
// Usage: node e2e/review-walk.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { inspect, mobile } from './screenCheck.mjs';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:19180';
const ko = JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8'));
const RUN_TIMEOUT = 420_000;
mkdirSync(out, { recursive: true });

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  locale: 'ko',
  reducedMotion: 'reduce',
});
const page = await context.newPage();
const problems = [];
const report = [];
const texts = [];
const visited = [];
page.on('pageerror', (e) =>
  problems.push({ kind: 'pageerror', at: page.url(), text: String(e).slice(0, 300) }),
);
page.on('console', (message) => {
  if (message.type() === 'error')
    problems.push({ kind: 'console', at: page.url(), text: message.text().slice(0, 300) });
});
page.on('response', (response) => {
  if (response.status() >= 400 && response.url().includes('/api/')) {
    problems.push({ kind: 'http', at: page.url(), text: `${response.status()} ${response.url()}` });
  }
});

const mainButton = () => page.locator('[data-zone="actions"] [data-main]');

async function api(path) {
  return page.evaluate((target) => fetch(target).then((r) => (r.ok ? r.json() : null)), path);
}

async function record(name, language) {
  await page.waitForLoadState('networkidle').catch(() => undefined);
  await page.waitForTimeout(800);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
    await page.waitForTimeout(300);
    await page.screenshot({ path: join(out, `${name}-${language}-${width}.png`), fullPage: true });
    report.push({
      name,
      language,
      width,
      url: page.url(),
      ...(await inspect(page)),
      ...(width === 390 ? { phone: await mobile(page) } : {}),
    });
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  texts.push({ name, language, url: page.url(), text: await page.evaluate(() => document.body.innerText) });
  if (language === 'ko') visited.push({ name, url: page.url() });
}

async function next(pattern) {
  await mainButton().click();
  await page.waitForURL(pattern, { timeout: 60_000 });
}

async function waitRun(scenario) {
  const deadline = Date.now() + RUN_TIMEOUT;
  while (Date.now() < deadline) {
    const run = await api('/api/live/runs/current');
    if (
      run &&
      (!scenario || run.scenario === scenario) &&
      ['COMPLETED', 'FAILED', 'EXPIRED'].includes(run.status)
    ) {
      return run.status;
    }
    await page.waitForTimeout(2_000);
  }
  return 'TIMEOUT';
}

async function send(call, consolePattern, name) {
  await page.getByText(ko[`main.request.call.${call}`], { exact: true }).click();
  await mainButton().click();
  await page.waitForURL(consolePattern, { timeout: 60_000 });
  await page.waitForTimeout(4_000);
  await page.screenshot({ path: join(out, `${name}-running-ko-1440.png`), fullPage: true });
  const status = await waitRun(null);
  await page.waitForFunction(
    ([selector, text]) => document.querySelector(selector)?.textContent?.includes(text),
    ['[data-zone="actions"] [data-main]', ko[`main.${name}.cta`]],
    { timeout: RUN_TIMEOUT },
  );
  return status;
}

async function answerChecks() {
  const deadline = Date.now() + RUN_TIMEOUT * 2;
  while (Date.now() < deadline) {
    const run = await api('/api/live/runs/current');
    if (run?.scenario === 'S14' && ['COMPLETED', 'FAILED', 'EXPIRED'].includes(run.status)) return run.status;
    const useCode = page.getByRole('button', { name: ko['try.challenge.useCode'] });
    const requestCode = page.getByRole('button', { name: ko['try.challenge.requestCode'] });
    // A button can be replaced while the check moves on; a missed press is tried again on the next pass.
    if (await useCode.isVisible().catch(() => false)) await useCode.click({ timeout: 5_000 }).catch(() => undefined);
    else if (await requestCode.isVisible().catch(() => false))
      await requestCode.click({ timeout: 5_000 }).catch(() => undefined);
    await page.waitForTimeout(1_000);
  }
  return 'TIMEOUT';
}

const sends = [];
let attackRun = null;
const step = async (label, fn) => {
  try {
    await fn();
  } catch (e) {
    problems.push({ kind: 'flow', at: page.url(), text: `${label}: ${String(e).slice(0, 300)}` });
    await page
      .screenshot({ path: join(out, `flow-failed-${label}.png`), fullPage: true })
      .catch(() => undefined);
    throw e;
  }
};

try {
  await step('opening', async () => {
    await page.goto(`${base}/?lng=ko`, { waitUntil: 'networkidle' });
    await record('1-1', 'ko');
  });
  await step('map', async () => {
    await next(/\/intro\/map/);
    await record('1-2', 'ko');
  });
  await step('attack', async () => {
    await next(/\/attack$/);
    await record('2-0', 'ko');
    await next(/\/attack\/request/);
    await record('2-1', 'ko');
    sends.push({ name: 'attack', status: await send('BLOCK', /\/attack\/console/, '2-2') });
    attackRun = (await api('/api/live/runs/current'))?.runId ?? null;
    await record('2-2', 'ko');
    await next(/\/attack\/result/);
    await record('2-3', 'ko');
  });
  await step('evidence', async () => {
    await next(/\/evidence$/);
    await record('3-0', 'ko');
    await next(/\/evidence\/map/);
    await record('3-1', 'ko');
    await next(/\/evidence\/prompt/);
    await record('3-2', 'ko');
    await next(/\/evidence\/verdict/);
    await record('3-3', 'ko');
  });
  await step('normal', async () => {
    await next(/\/normal$/);
    await record('4-0', 'ko');
    await next(/\/normal\/request/);
    await record('4-1', 'ko');
    sends.push({ name: 'owner', status: await send('ALLOW', /\/normal\/console/, '4-2') });
    await record('4-2', 'ko');
    await next(/\/normal\/diff/);
    await record('4-3', 'ko');
    await next(/\/normal\/check/);
    await record('4-4-before', 'ko');
    await mainButton().click();
    await page.waitForTimeout(4_000);
    await page.screenshot({ path: join(out, '4-4-running-ko-1440.png'), fullPage: true });
    sends.push({ name: 'checked', status: await answerChecks() });
    await record('4-4', 'ko');
  });
  await step('insider', async () => {
    await next(/\/insider$/);
    await record('5-0', 'ko');
    await next(/\/insider\/request/);
    await record('5-1', 'ko');
    sends.push({ name: 'insider', status: await send('BLOCK', /\/insider\/console/, '5-2') });
    await record('5-2', 'ko');
    await next(/\/insider\/reason/);
    await record('5-3', 'ko');
  });
  // docs/agent A7-3: the business agent group; the visitor answers the confirmation as the delegating employee.
  await step('agent', async () => {
    await next(/\/agent$/);
    await record('6-0', 'ko');
    await next(/\/agent\/request/);
    await record('6-1', 'ko');
    await page.getByText(ko['main.6-1.call.BLOCK'], { exact: true }).click();
    await mainButton().click();
    await page.waitForURL(/\/agent\/console/, { timeout: 60_000 });
    await page.waitForFunction(
      ([selector, text]) => document.querySelector(selector)?.textContent?.includes(text),
      ['[data-zone="actions"] [data-main]', ko['main.6-2.cta']],
      { timeout: RUN_TIMEOUT },
    );
    await record('6-2', 'ko');
    await next(/\/agent\/reason/);
    await record('6-3', 'ko');
    await next(/\/agent\/confirm/);
    await record('6-4-asked', 'ko');
    const approve = page.getByRole('button', { name: ko['main.6-4.approve'] });
    if ((await approve.count()) > 0) {
      await approve.click();
    }
    sends.push({ name: 'agent', status: await waitRun('T5') });
    await page.waitForTimeout(3_000);
    await record('6-4', 'ko');
  });
  await step('compare', async () => {
    await next(/\/compare$/);
    await record('7-0', 'ko');
    await next(/\/compare\/rule/);
    await record('7-1', 'ko');
    await next(/\/compare\/change/);
    await record('7-2-before', 'ko');
    await page.getByRole('button', { name: ko['main.7-2.send'] }).click();
    await page.waitForURL(/sent=/, { timeout: 60_000 });
    sends.push({ name: 'changed', status: await waitRun(null) });
    await page.waitForTimeout(8_000);
    await record('7-2', 'ko');
    await next(/\/compare\/runs/);
    await record('7-3', 'ko');
  });
  await step('summary', async () => {
    await next(/\/summary$/);
    await record('8-1', 'ko');
    await next(/\/summary\/next/);
    await record('8-2', 'ko');
  });
} catch {
  // The flow stopped; the problem is recorded and the other screens are still walked.
}

const STATIC = [
  ['more', '/more'],
  ['learn-why', '/intro/learning'],
  ['learned', '/intro/learning/learned'],
  ['how', '/intro/how'],
  ['stack', '/try/stack'],
  ['timing-concept', '/try/timing/concept'],
  ['timing-try', '/try/timing/try'],
  ['timing-compare', '/try/timing/compare'],
  ['timing-when', '/try/timing/when'],
  ['follow', '/try/follow'],
  ['learn-after', '/try/summary/learning'],
  ['approaches', '/intro/approaches'],
  ['replay', '/replay/A3'],
  ['adopt', '/adopt'],
  ['privacy', '/privacy'],
  ['lab-0', '/lab'],
  ['lab-1', '/lab/case'],
  ['lab-2', '/lab/change?case=A3T&field=approval'],
  ['lab-before', '/lab/before?case=A3T&approval=false'],
  ['lab-send', '/lab/send?case=A3T&approval=false'],
  ['lab-rules', '/lab/rules'],
  ['bench-summary', '/benchmark'],
  ['bench-approaches', '/benchmark/approaches'],
  ['bench-cases', '/benchmark/cases'],
  ['bench-case', '/benchmark/cases/S13'],
  ['bench-judgment', '/benchmark/judgment'],
  ['bench-reasoning', '/benchmark/reasoning'],
  ['bench-limits', '/benchmark/limits'],
];
for (const [name, path] of STATIC) {
  try {
    await page.goto(`${base}${path}${path.includes('?') ? '&' : '?'}lng=ko`, { waitUntil: 'networkidle' });
    await record(name, 'ko');
  } catch (e) {
    problems.push({ kind: 'static', at: path, text: String(e).slice(0, 300) });
  }
}
if (attackRun) {
  for (const tab of ['summary', 'received', 'process', 'prompt', 'rules', 'answer', 'original']) {
    try {
      await page.goto(`${base}/run/${attackRun}/detail?step=1&tab=${tab}&lng=ko`, {
        waitUntil: 'networkidle',
      });
      await record(`detail-${tab}`, 'ko');
    } catch (e) {
      problems.push({ kind: 'static', at: `detail ${tab}`, text: String(e).slice(0, 300) });
    }
  }
}

// One lab run of the streamed export: the live bars while the stream is read and after Contexa answered.
try {
  await page.goto(`${base}/lab/send?case=A3S&lng=ko`, { waitUntil: 'networkidle' });
  await page
    .locator('label')
    .filter({ has: page.getByRole('radio', { name: ko['lab.r7.send.call.ATTACK'] }) })
    .click();
  await page.getByRole('button', { name: ko['lab.r7.send.send'] }).click();
  await page.waitForURL(/sent=/, { timeout: 60_000 });
  for (const at of [4, 9, 20]) {
    await page.waitForTimeout(at === 4 ? 4_000 : at === 9 ? 5_000 : 11_000);
    await page.screenshot({ path: join(out, `lab-stream-${at}s-ko-1440.png`), fullPage: true });
  }
  await page.getByRole('link', { name: ko['lab.r7.run.next'] }).waitFor({ timeout: RUN_TIMEOUT });
  sends.push({ name: 'lab A3S', status: 'ENDED' });
  await record('lab-run', 'ko');
  await page.getByRole('link', { name: ko['lab.r7.run.next'] }).click();
  await page.waitForURL(/\/lab\/result/);
  await record('lab-result', 'ko');
} catch (e) {
  problems.push({ kind: 'flow', at: page.url(), text: `lab A3S: ${String(e).slice(0, 300)}` });
}

// R-12 of the review: the case list with every folded group open, and the case sheet on a tall phone.
try {
  await page.goto(`${base}/benchmark/cases?lng=ko`, { waitUntil: 'networkidle' });
  await page.evaluate(() => document.querySelectorAll('details').forEach((details) => (details.open = true)));
  await record('bench-cases-open', 'ko');
  await page.goto(`${base}/benchmark/cases/S13?lng=ko`, { waitUntil: 'networkidle' });
  await page.setViewportSize({ width: 390, height: 2400 });
  await page.waitForTimeout(500);
  await page.screenshot({ path: join(out, 'bench-case-tall-ko-390.png') });
  await page.setViewportSize({ width: 1440, height: 900 });
} catch (e) {
  problems.push({ kind: 'static', at: 'bench open', text: String(e).slice(0, 300) });
}

// The same screens in English, with the visitor's journey as it now stands. A screen captured before a send ('-before')
// is captured from a fresh visitor instead, since the visitor's own later run would show on it (R-11).
const fresh = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'en', reducedMotion: 'reduce' });
const freshPage = await fresh.newPage();
for (const { name, url } of [...visited]) {
  if (name.endsWith('-before')) {
    try {
      const target = new URL(url);
      target.searchParams.set('lng', 'en');
      await freshPage.goto(target.toString(), { waitUntil: 'networkidle' });
      await freshPage.waitForTimeout(800);
      for (const width of [1440, 390]) {
        await freshPage.setViewportSize({ width, height: width === 390 ? 844 : 900 });
        await freshPage.waitForTimeout(300);
        await freshPage.screenshot({ path: join(out, `${name}-en-${width}.png`), fullPage: true });
      }
      texts.push({ name, language: 'en', url: freshPage.url(), text: await freshPage.evaluate(() => document.body.innerText) });
    } catch (e) {
      problems.push({ kind: 'static-en', at: url, text: String(e).slice(0, 300) });
    }
    continue;
  }
  try {
    const target = new URL(url);
    target.searchParams.set('lng', 'en');
    await page.goto(target.toString(), { waitUntil: 'networkidle' });
    await record(name, 'en');
  } catch (e) {
    problems.push({ kind: 'static-en', at: url, text: String(e).slice(0, 300) });
  }
}

await fresh.close();
await browser.close();
writeFileSync(join(out, 'review.json'), JSON.stringify({ sends, problems, report }, null, 1));
for (const language of ['ko', 'en']) {
  writeFileSync(
    join(out, `texts-${language}.md`),
    texts
      .filter((entry) => entry.language === language)
      .map((entry) => `## ${entry.name} (${entry.url.replace(base, '')})\n\n${entry.text}\n`)
      .join('\n'),
  );
}
const issues = report.filter((row) => row.overflow > 0 || row.singleLetter?.length || row.serious?.length);
console.log(
  JSON.stringify(
    { sends, screens: texts.length, problems: problems.length, layoutIssues: issues.length },
    null,
    1,
  ),
);
