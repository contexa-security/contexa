// S12 C-3 on the real stack: the information limits of every visitor screen (limits slide, plan 7절), counted at
// 1440 x 900 in Korean by a visitor who sent try 1 and try 2 (the guide video's visitor), so the result steps hold runs.
//   guidance   the purpose line and the screen's lead sentences: how many sentences, and the longest in characters
//   blocks     the content blocks of the step: the children of the step's column other than the head, the row of
//              "open" chips, the "just seen" band, the role band and the action area
//   main       main buttons (data-main); secondary = the other links and buttons of the action area (teaser excluded)
//   inputs     visible question groups (fieldset) plus inputs outside them
//   numbers    numbers in the main area (screenCheck's count), terms = distinct first-use term buttons
//   height     the page's scroll height at 1440 x 900 (one step of about 900 px)
// For C-17 it also records tables, English words, whether the place band and a role band are on screen, and the main
// button's words.
// Usage: node e2e/s12-limits.mjs <out dir> <visitor state json> [base url]
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

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  locale: 'ko',
  reducedMotion: 'reduce',
  storageState: state,
});
const page = await context.newPage();
const report = [];
for (const [name, path, root = 'main'] of SCREENS) {
  await page.goto(`${base}${path}${path.includes('?') ? '&' : '?'}lng=ko`, { waitUntil: 'networkidle' });
  await page.locator(`${root} h1, ${root} h2`).first().waitFor({ timeout: 20_000 });
  await page.waitForTimeout(800);
  const counted = await page.evaluate(
    ({ root, actions, more, place }) => {
      const visible = (element) => {
        // Inside a closed fold only its summary shows (Chrome still gives the hidden content a box).
        if (element.closest('details:not([open])') && !element.closest('summary')) return false;
        const box = element.getBoundingClientRect();
        const style = getComputedStyle(element);
        return box.width > 0 && box.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
      };
      const scope = document.querySelector(root);
      const head = scope.querySelector('h1')?.closest('header') ?? scope.querySelector('h1, h2');
      const column = head?.parentElement ?? scope;
      const isAside = (element) =>
        element === head ||
        element.matches(`nav[aria-label="${actions}"], [role="group"][aria-label="${more}"], p[role="note"], p[role="status"]`);
      const blocks = [...column.children].filter((element) => visible(element) && !isAside(element));
      const sentences = (text) =>
        text
          .replace(/\s+/g, ' ')
          .split(/(?<=[.?!。])\s+/)
          .map((part) => part.trim())
          .filter((part) => part.length > 0);
      const purpose = head?.querySelector('h1 + p, h1 ~ p')?.textContent ?? '';
      const leads = [...column.querySelectorAll('[class*="_lead_"]')].filter(visible).map((p) => p.textContent ?? '');
      const guidance = [purpose, ...leads].flatMap(sentences);
      const actionArea = column.querySelector(`nav[aria-label="${actions}"]`);
      const secondary = actionArea
        ? [...actionArea.querySelectorAll('a, button')].filter(
            (element) => visible(element) && !element.hasAttribute('data-main') && !element.closest('[data-teaser]'),
          ).length
        : 0;
      const fieldsets = [...column.querySelectorAll('fieldset')].filter(visible);
      // A group of radio buttons or checkboxes with one name is one question, like a fieldset.
      const groups = new Set();
      const loose = [...column.querySelectorAll('input:not([type="hidden"]), select, textarea')].filter((element) => {
        if (!visible(element) || element.closest('fieldset')) return false;
        if ((element.type === 'radio' || element.type === 'checkbox') && element.name) {
          if (groups.has(element.name)) return false;
          groups.add(element.name);
        }
        return true;
      });
      const terms = new Set(
        [...column.querySelectorAll('[data-term]')].filter(visible).map((element) => element.textContent?.trim()),
      );
      const mainButton = scope.querySelector('[data-main]');
      return {
        tables: [...column.querySelectorAll('table')].filter(visible).length,
        placeBand: document.querySelector(`main nav[aria-label="${place}"]`) !== null,
        roleBand: column.querySelector('p[role="status"]') !== null,
        mainWords: mainButton?.textContent?.trim() ?? '',
        blocks: blocks.length,
        guidanceSentences: guidance.length,
        longestSentence: Math.max(0, ...guidance.map((sentence) => sentence.length)),
        secondary,
        inputs: fieldsets.length + loose.length,
        terms: terms.size,
        height: document.documentElement.scrollHeight,
        stepHeight: Math.round(column.getBoundingClientRect().height),
        guideText: guidance.filter((sentence) => sentence.length > 44),
        heading: scope.querySelector('h1, h2')?.textContent?.trim() ?? '',
      };
    },
    { root, actions: m['step.actions'], more: m['step.more'], place: m['place.label'] },
  );
  const checks = await inspect(page, root);
  report.push({
    name,
    path,
    ...counted,
    main: checks.limits.primaries,
    numbers: checks.limits.numbers,
    english: checks.limits.english,
  });
  console.log(
    `${name.padEnd(15)} blocks ${String(counted.blocks).padStart(2)} guide ${counted.guidanceSentences}/${String(counted.longestSentence).padStart(3)}` +
      ` main ${checks.limits.primaries} side ${counted.secondary} inputs ${counted.inputs} numbers ${String(checks.limits.numbers).padStart(2)}` +
      ` terms ${counted.terms} height ${counted.height}/${counted.stepHeight}`,
  );
}
writeFileSync(join(out, 'limits.json'), JSON.stringify(report, null, 2));
await browser.close();
