// The redesign's check of the screens that only appear after a real send (docs/showcase/화면재편-구현계획.md R2, RC-1
// to RC-3): it walks try 1 and try 2 on a running portal as a visitor does, picks a call, sends it for real, and
// measures and judges every screen on the way at 1440, 1024, 768 and 390 px with the same rules as frame-audit.mjs. One real run
// per try goes through the visitor's own gate. Exits 1 when any screen fails.
// Usage: node e2e/frame-live.mjs <outDir> [--base <url>] [--lang ko|en] [--call <label>] [--until <part 2-5>]
// With --until above 2 it goes on from part 2's wrap-up to the end of that part (R4-R6), sending the screens whose
// main button is a send button (3-3 try 3, 4-1 the resend) for real.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';
import { judge, measure } from './frameMeasure.mjs';
import { inspect } from './screenCheck.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
const outDir = args[0];
const base = option('--base', 'http://127.0.0.1:19180');
const lang = option('--lang', 'ko');
const call = option('--call', lang === 'en' ? 'Identity check' : '본인 확인');
const until = Number(option('--until', '2'));
const route = JSON.parse(fs.readFileSync(path.join(here, '..', 'src', 'journey', 'route.json'), 'utf8'));
// The copy of the language under check: its main buttons are pressed by name and its keys are compared (RC-3).
const ko = JSON.parse(fs.readFileSync(path.join(here, '..', 'src', 'i18n', `${lang}.json`), 'utf8'));
const byPath = new Map(route.map((screen) => [screen.path, screen]));
fs.mkdirSync(outDir, { recursive: true });

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, locale: lang });
await context.addInitScript((language) => {
  try {
    localStorage.setItem('showcase.language', language);
  } catch {
    // Storage may be closed; the browser language decides then.
  }
}, lang);
const page = await context.newPage();
const results = [];

/** The screen an address shows: a run sent from 4-1 ("from=timing") plays on the try's run step and belongs to 4-1. */
function screenOf(address) {
  const url = new URL(address);
  const fromTiming = url.searchParams.get('from')?.startsWith('timing') && url.pathname.endsWith('/run');
  return byPath.get(fromTiming ? '/try/timing/try' : url.pathname);
}

async function check(label) {
  const screen = screenOf(page.url()) ?? { id: label };
  for (const [width, height] of [[1440, 1000], [1024, 900], [768, 900], [390, 844]]) {
    await page.setViewportSize({ width, height });
    await page.waitForTimeout(900);
    const m = await page.evaluate(measure);
    const id = `${screen.number ?? '-'}-${label}`;
    await page.screenshot({ path: path.join(outDir, `${id}-${width}.png`), fullPage: true });
    const fails = judge(screen, width, m, ko, false, lang);
    // The checks the old step scripts made (s3-act1, plan 2.5): one letter left alone on a line, serious or critical
    // axe findings, and Korean left on an English screen.
    const seen = await inspect(page);
    if (seen.singleLetter.length) fails.push(`single letter on a line: ${seen.singleLetter.slice(0, 2).join(' | ')}`);
    if (seen.serious.length) fails.push(`axe: ${seen.serious.map((v) => v.id).join(', ')}`);
    if (lang === 'en' && seen.limits?.korean.length) fails.push(`Korean on the English screen: ${seen.limits.korean.join(' ')}`);
    const { pageText, ...kept } = m;
    results.push({ id, url: page.url().replace(base, ''), width, ...kept, fails });
    console.log(width, id, fails.length ? `FAIL ${fails.length}: ${fails.slice(0, 5).join('; ')}` : 'PASS');
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
}

async function next() {
  const button = page.locator('[data-zone="actions"] [data-main]');
  await button.waitFor({ timeout: 30000 });
  await button.click();
  await page.waitForLoadState('load');
  await page.locator('h1').first().waitFor({ timeout: 15000 });
  await page.waitForTimeout(1500);
}

async function sendTry(role) {
  await page.goto(`${base}/try/${role}/predict`, { waitUntil: 'load' });
  await page.locator('h1').first().waitFor({ timeout: 15000 });
  await page.waitForTimeout(1500);
  await check(`${role}-predict-before`);
  await page.getByText(call, { exact: true }).first().click();
  await page.getByRole('button', { name: ko['p1.predict.send'] }).click();
  await page.waitForURL(new RegExp(`/try/${role}/run`), { timeout: 60000 });
  await page.waitForTimeout(4000);
  await check(`${role}-running`);
  await page.getByRole('link', { name: ko['screen.1-3.next'] }).waitFor({ timeout: 300000 });
  await page.waitForTimeout(1500);
  await check(`${role}-run-done`);
}

// Try 1: predict, run, result, reason, after, the part's wrap-up, and on to try 2's cover.
await sendTry('attacker');
for (const label of ['attacker-result', 'attacker-reason', 'attacker-after', 'part1-wrap', 'owner-cover']) {
  await next();
  await check(label);
}
// Try 2: predict, run, result, reason, the identity check, what follows each judgment, and the part's wrap-up (R3).
await sendTry('owner');
for (const label of ['owner-result', 'owner-reason', 'owner-check', 'follow', 'part2-wrap']) {
  await next();
  await check(label);
}

// Parts 3 to 5 (R4-R6): the one main button screen by screen up to the last screen of the part asked for. A screen
// whose main button is a send button is sent for real, measured while it runs, and measured again once its link to
// the next screen appears.
if (until > 2) {
  const last = route.filter((screen) => screen.act === until).at(-1)?.path;
  for (let i = 0; i < 40; i += 1) {
    const here = new URL(page.url()).pathname;
    if (here === last) {
      break;
    }
    const button = page.locator('[data-zone="actions"] [data-main]');
    await button.waitFor({ timeout: 30000 });
    if ((await button.evaluate((element) => element.tagName)) === 'BUTTON') {
      const sent = byPath.get(here)?.id ?? here;
      await button.click();
      await page.waitForTimeout(4000);
      await check(`${sent}-running`);
      // A request the visitor sends themselves (visitorSends, 4-1's second request) is sent as a visitor would.
      const link = page.locator('[data-zone="actions"] a[data-main]');
      const sendNext = page.getByRole('button', { name: ko['p1.run.sendNext'] });
      for (let wait = 0; wait < 600 && !(await link.isVisible()); wait += 2) {
        if (await sendNext.isVisible()) {
          await sendNext.click();
        }
        await page.waitForTimeout(2000);
      }
      await link.waitFor({ timeout: 10000 });
      await page.waitForTimeout(1500);
      await check(`${sent}-done`);
      continue;
    }
    await next();
    await check(screenOf(page.url())?.id ?? 'screen');
  }
}

await browser.close();
fs.writeFileSync(path.join(outDir, 'frame-live.json'), JSON.stringify(results, null, 1));
const failed = results.filter((r) => r.fails.length);
console.log(`done ${results.length} checks, ${failed.length} failing`);
process.exit(failed.length ? 1 : 0);
