// S12 C-10 on the real stack: the teaser cards of the 15 places of the 0-3 table (journey.ts) against the portal's
// /api/teasers. Every number on a card's number line must be one of the API values of that card (milliseconds also as
// the screen's seconds), the card must carry the "measured" mark when the API names a source, and a card whose fact
// condition is false (holds = false) must show the approved fallback words. G_LEARNED_FLOW is fixed words; the dilemma
// card counts the visitor's differences, compared with the journey state.
// Usage: node e2e/s12-teasers.mjs <out dir> <visitor state json> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const state = process.argv[3];
const base = process.argv[4] ?? 'http://127.0.0.1:19180';
const m = JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8'));
mkdirSync(out, { recursive: true });

const PLACES = [
  ['HOOK_TRY', '/'],
  ['E1_RESULT_FACTS', '/try/attacker/result'],
  ['E1_REASON_MAILBOX', '/try/attacker/reason'],
  ['E1_AFTER_RULES', '/try/attacker/end'],
  ['E2_RESULT_DIFF', '/try/owner/result'],
  ['G_RULES_RESUME', '/intro/how/rules'],
  ['FOLLOW_LEARNED', '/try/follow/end'],
  ['LEARN_WHY_TAUGHT', '/intro/learning'],
  ['G_LEARNED_FLOW', '/intro/learning/learned'],
  ['G_HOW_LINES', '/intro/how'],
  ['E1_PROMPT_ASYNC', '/try/prompt'],
  ['SYNC_WHEN_OBSERVATIONS', '/try/timing/when'],
  ['LEARN_AFTER_FALSE_BLOCKS', '/try/summary/learning/end'],
  ['G_WHERE_C2', '/intro/approaches/where'],
  ['DILEMMA_DIFFERENCES', '/try/summary/dilemma'],
];

function numbersIn(value, found = new Set()) {
  if (typeof value === 'number') {
    found.add(value.toLocaleString('ko-KR'));
    found.add(String(value));
    // Milliseconds are shown as seconds with one decimal (plan 1절 7).
    found.add((Math.round(value / 100) / 10).toFixed(1));
    found.add((value / 1000).toFixed(2));
  } else if (Array.isArray(value)) {
    value.forEach((item) => numbersIn(item, found));
  } else if (value && typeof value === 'object') {
    Object.values(value).forEach((item) => numbersIn(item, found));
  }
  return found;
}

const teasers = (await (await fetch(`${base}/api/teasers`)).json()).teasers;
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko', storageState: state });
const page = await context.newPage();
const report = [];
for (const [key, path] of PLACES) {
  await page.goto(`${base}${path}?lng=ko`, { waitUntil: 'networkidle' });
  await page.locator('main h1').first().waitFor({ timeout: 20_000 });
  await page.waitForTimeout(800);
  const card = page.locator('[data-teaser]').first();
  const present = (await card.count()) > 0;
  const text = present ? (await card.innerText()).replace(/\s+/g, ' ').trim() : '';
  const lines = present
    ? await card.evaluate((element) => [...element.children].map((child) => child.textContent?.trim() ?? ''))
    : [];
  const numberLine = lines[2] ?? '';
  const shown = numberLine.match(/\d[\d,.]*/g) ?? [];
  const item = teasers.find((candidate) => candidate.key === key) ?? null;
  const problems = [];
  if (!present) {
    problems.push('no teaser card');
  } else if (key === 'G_LEARNED_FLOW') {
    if (!text.includes(m['teaser.G_LEARNED_FLOW.teaser'])) problems.push('fixed words differ');
  } else if (key === 'DILEMMA_DIFFERENCES') {
    const journey = await page.evaluate(() => fetch('/api/journey').then((r) => r.json()));
    const seen = String(journey.state.differences.length);
    if (!shown.includes(seen)) problems.push(`differences ${shown.join(',')} != journey ${seen}`);
  } else if (!item) {
    problems.push('no API item');
  } else {
    const allowed = numbersIn(item.values);
    const strange = shown.filter((number) => !allowed.has(number));
    if (strange.length > 0) problems.push(`numbers not from the API: ${strange.join(', ')}`);
    if (item.source && !text.includes(m['source.measured'])) problems.push('no measured mark');
    if (item.holds === false && !text.includes((m[`teaser.${key}.fallback`] ?? '\u0000').split('{{')[0])) {
      problems.push('fact false but the fallback words are not shown');
    }
  }
  report.push({ key, path, present, text, numberLine, shown, holds: item?.holds ?? null, problems });
  console.log(`${key.padEnd(26)} ${problems.length === 0 ? 'ok' : problems.join(' | ')}  [${numberLine}]`);
}
writeFileSync(join(out, 'teasers.json'), JSON.stringify(report, null, 2));
await browser.close();
