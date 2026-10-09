// S12 C-7 on the real stack: on every screen of acts 1-4, the concept path and the lab, a reload keeps the screen; the
// main button's next screen and the browser's back button come back to the same address and heading; the glossary
// window opened from the menu closes back to the same address, scroll position and focus. A main button that sends a
// live run is not pressed. Usage: node e2e/s12-navigation.mjs <out dir> <visitor state json> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const state = process.argv[3];
const base = process.argv[4] ?? 'http://127.0.0.1:19180';
const m = JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8'));
mkdirSync(out, { recursive: true });

const PATHS = [
  '/', '/try/attacker/scene', '/try/attacker/compare', '/try/attacker/predict', '/try/attacker/run',
  '/try/attacker/result', '/try/attacker/reason', '/try/attacker/after', '/try/attacker/end',
  '/try/owner/scene', '/try/owner/compare', '/try/owner/predict', '/try/owner/run', '/try/owner/result',
  '/try/owner/reason', '/intro/how/rules', '/try/owner/after', '/try/follow', '/try/follow/end',
  '/intro/learning', '/intro/learning/learned', '/intro/how', '/try/prompt', '/try/timing/concept',
  '/try/timing/try', '/try/timing/compare', '/try/timing/when', '/try/stack', '/try/summary/learning',
  '/try/summary/learning/end', '/intro/approaches', '/intro/approaches/where', '/try/summary/dilemma',
  '/try/summary/recap', '/try/summary/quiz', '/try/summary/value', '/try/summary/adopt',
  '/intro?route=intro', '/intro/concept?route=intro', '/intro/compare?route=intro', '/intro/order?route=intro',
  '/lab', '/lab/case?case=A3T', '/lab/change?case=A3T&field=approval', '/lab/before?case=A3T&approval=false',
  '/lab/rules',
];

const heading = (page) => page.locator('main h1').first().innerText();
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko', storageState: state });
const page = await context.newPage();
const report = [];
for (const path of PATHS) {
  const address = `${base}${path}${path.includes('?') ? '&' : '?'}lng=ko`;
  const problems = [];
  await page.goto(address, { waitUntil: 'networkidle' });
  await page.locator('main h1').first().waitFor({ timeout: 20_000 });
  const title = await heading(page);
  const url = page.url();

  await page.reload({ waitUntil: 'networkidle' });
  await page.locator('main h1').first().waitFor({ timeout: 20_000 });
  if ((await heading(page)) !== title || page.url() !== url) problems.push('reload changed the screen');

  // The glossary window from the menu closes back to the same place, focus on the menu's button.
  // The place the window opens from is where the page stands once the menu's button is in view (the click itself
  // scrolls to it); closing must come back there.
  await page.evaluate(() => window.scrollTo(0, 300));
  const open = page.locator('header').getByRole('button', { name: m['glossary.open'], exact: true });
  await open.scrollIntoViewIfNeeded();
  const scrolled = await page.evaluate(() => window.scrollY);
  await open.click();
  await page.getByRole('dialog').waitFor();
  await page.keyboard.press('Escape');
  await page.getByRole('dialog').waitFor({ state: 'hidden' });
  if (page.url() !== url) problems.push(`glossary closed to ${page.url()}`);
  if (Math.abs((await page.evaluate(() => window.scrollY)) - scrolled) > 2) problems.push('glossary lost the scroll');
  if (!(await open.evaluate((element) => element === document.activeElement))) problems.push('focus not back on the menu');

  const main = page.locator('main [data-main]').first();
  const isLink = (await main.count()) > 0 && (await main.evaluate((element) => element.tagName === 'A'));
  if (isLink && !(await main.evaluate((element) => element.getAttribute('aria-disabled') === 'true'))) {
    await main.click();
    await page.waitForURL((next) => next.toString() !== url, { timeout: 10_000 }).catch(() => undefined);
    await page.locator('main h1').first().waitFor({ timeout: 20_000 });
    const nextUrl = page.url();
    await page.goBack({ waitUntil: 'networkidle' });
    await page.locator('main h1').first().waitFor({ timeout: 20_000 });
    if (page.url() !== url || (await heading(page)) !== title) {
      problems.push(`back from ${nextUrl} came to ${page.url()}`);
    }
  }
  report.push({ path, title, problems, next: isLink });
  console.log(`${path.padEnd(42)} ${problems.length === 0 ? 'ok' : problems.join(' | ')}`);
}
writeFileSync(join(out, 'navigation.json'), JSON.stringify(report, null, 2));
await browser.close();
