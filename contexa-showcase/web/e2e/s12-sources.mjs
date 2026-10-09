// S12 C-2 on the real stack: the source marks of every visitor screen (plan 1절 4, rule U-4: one source mark in a
// screen's content for its main record, other sources inside that box; a teaser keeps its own "measured" mark). For each
// screen at 1440 x 900 in Korean, by the visitor who sent try 1 and try 2: the numbers in the content, the content's
// source marks (teaser cards apart), and what the first mark's box names: the kind of source, a run number or another
// record id (measurement setting, protocol, case key), and the recorded time in UTC.
// Usage: node e2e/s12-sources.mjs <out dir> <visitor state json> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { inspect } from './screenCheck.mjs';

const out = process.argv[2];
const state = process.argv[3];
const base = process.argv[4] ?? 'http://127.0.0.1:19180';
const m = JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8'));
mkdirSync(out, { recursive: true });

const benchmark = await (await fetch(`${base}/api/benchmark`)).json();
const run = benchmark.cases.find((row) => row.key === 'A3')?.runIds[0];

const SCREENS = [
  ['hook', '/'],
  ['e1-scene', '/try/attacker/scene'],
  ['e1-compare', '/try/attacker/compare'],
  ['e1-predict', '/try/attacker/predict'],
  ['e1-run', '/try/attacker/run'],
  ['e1-result', '/try/attacker/result'],
  ['e1-reason', '/try/attacker/reason'],
  ['e1-after', '/try/attacker/after'],
  ['act1-end', '/try/attacker/end'],
  ['e2-scene', '/try/owner/scene'],
  ['e2-compare', '/try/owner/compare'],
  ['e2-predict', '/try/owner/predict'],
  ['e2-run', '/try/owner/run'],
  ['e2-result', '/try/owner/result'],
  ['e2-reason', '/try/owner/reason'],
  ['g-rules', '/intro/how/rules'],
  ['e2-check', '/try/owner/after'],
  ['follow', '/try/follow'],
  ['act2-end', '/try/follow/end'],
  ['learn-why', '/intro/learning'],
  ['learned', '/intro/learning/learned'],
  ['how', '/intro/how'],
  ['prompt', '/try/prompt'],
  ['timing-concept', '/try/timing/concept'],
  ['timing-try', '/try/timing/try'],
  ['timing-compare', '/try/timing/compare'],
  ['timing-when', '/try/timing/when'],
  ['stack', '/try/stack'],
  ['learn-after', '/try/summary/learning'],
  ['act3-end', '/try/summary/learning/end'],
  ['approaches', '/intro/approaches'],
  ['where', '/intro/approaches/where'],
  ['dilemma', '/try/summary/dilemma'],
  ['recap', '/try/summary/recap'],
  ['quiz', '/try/summary/quiz'],
  ['value', '/try/summary/value'],
  ['adopt-change', '/try/summary/adopt'],
  ['g1', '/intro?route=intro'],
  ['g2', '/intro/concept?route=intro'],
  ['g4', '/intro/compare?route=intro'],
  ['g5', '/intro/order?route=intro'],
  ['lab-0', '/lab'],
  ['lab-1', '/lab/case?case=A3T'],
  ['lab-2', '/lab/change?case=A3T&field=approval'],
  ['lab-compare', '/lab/before?case=A3T&approval=false'],
  ['lab-send', '/lab/send?case=A3T&approval=false'],
  ['lab-rules', '/lab/rules'],
  ['bench-summary', '/benchmark'],
  ['bench-cases', '/benchmark/cases'],
  ['bench-judgment', '/benchmark/judgment'],
  ['bench-limits', '/benchmark/limits'],
  ['replay', '/replay/A3'],
  ['adopt', '/adopt'],
  ['privacy', '/privacy'],
  ['detail', `/run/${run}/detail?step=1`, 'dialog[open]'],
];

const KINDS = ['ENGINE', 'BUSINESS', 'CASE', 'MEASUREMENT'].map((kind) => m[`source.kind.${kind}`]);
const MARK_WORDS = [m['source.button'], m['source.measured']];

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko', storageState: state });
const page = await context.newPage();
const report = [];
for (const [name, path, root = 'main'] of SCREENS) {
  await page.goto(`${base}${path}${path.includes('?') ? '&' : '?'}lng=ko`, { waitUntil: 'networkidle' });
  await page.locator(`${root} h1, ${root} h2`).first().waitFor({ timeout: 20_000 });
  await page.waitForTimeout(800);
  const checks = await inspect(page, root);
  // The content's marks; a mark inside a closed disclosure belongs to what it hides (C-3 counts the same way), so it is
  // counted apart.
  const { found, folded } = await page.evaluate(
    ({ root, words }) => {
      const marks = [...document.querySelector(root).querySelectorAll('button[aria-controls]')].filter(
        (button) => words.includes((button.textContent ?? '').trim()) && !button.closest('[data-teaser]'),
      );
      const closed = (button) => {
        const details = button.closest('details');
        return details !== null && !details.open;
      };
      return {
        found: marks.filter((button) => !closed(button)).map((button) => button.getAttribute('aria-controls')),
        folded: marks.filter(closed).length,
      };
    },
    { root, words: MARK_WORDS },
  );
  let box = '';
  let firstLine = '';
  if (found.length > 0) {
    const button = page.locator(`${root} button[aria-controls="${found[0]}"]`);
    if ((await button.getAttribute('aria-expanded')) !== 'true') {
      await button.click();
    }
    const opened = page.locator(`[id="${found[0]}"]`);
    // A run's recorded time arrives with the run's score after the box opens.
    await opened.getByText(/\(UTC\)/).first().waitFor({ timeout: 3000 }).catch(() => undefined);
    box = (await opened.innerText()).replace(/\s+/g, ' ');
    firstLine = ((await opened.locator('span').first().textContent()) ?? '').trim();
  }
  const kind = KINDS.find((word) => firstLine === word) ?? null;
  // On a screen without a mark, the numbers with their surrounding words, to judge whether they are records.
  const numbersText =
    found.length === 0 && checks.limits.numbers > 0
      ? await page.evaluate((selector) => {
          const text = (document.querySelector(selector)?.innerText ?? '').replace(/\s+/g, ' ');
          return [...text.matchAll(/.{0,12}\d[\d,.]*.{0,12}/g)].map((match) => match[0].trim()).slice(0, 8);
        }, root)
      : null;
  // A record id: a run, a measurement (protocol or setting, 8 hex or more), an employee template, or a case key.
  const ids =
    box.match(/run-[0-9a-f]{12}|protocol-[0-9a-f]{8}|\b[0-9a-f]{8,64}\b|tpl-[\w-]+|\b[A-Z]{1,2}\d{1,2}[A-Z]{0,2}\b/g) ?? [];
  report.push({
    name,
    path,
    numbers: checks.limits.numbers,
    marks: found.length,
    folded,
    kind,
    runIds: [...new Set(box.match(/run-[0-9a-f]{12}/g) ?? [])],
    ids: [...new Set(ids)].slice(0, 6),
    recordedAt: box.includes('(UTC)'),
    numbersText,
    box: box.slice(0, 240),
  });
  console.log(`${name.padEnd(15)} numbers ${String(checks.limits.numbers).padStart(2)} marks ${found.length} kind ${kind ?? '-'} ids ${[...new Set(ids)].slice(0, 3).join(',') || '-'} utc ${box.includes('(UTC)')}`);
}
writeFileSync(join(out, 'sources.json'), JSON.stringify(report, null, 2));
await browser.close();
