// S11 sweep on the real stack (C-4, C-5, C-8, mobile slide): every visitor screen in Korean and English. At 390,
// 768, 1024 and 1440 px each screen runs the screen checks; at 390 px also the phone rules (text of 16 px or more,
// pressable targets of 44 px or more, the main button fixed at the bottom). With --probe it measures without screenshots.
// Usage: node e2e/s11-sweep.mjs <out dir> [base url] [--probe]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { capture, inspect, mobile } from './screenCheck.mjs';

const out = process.argv[2];
const base = process.argv[3] && !process.argv[3].startsWith('--') ? process.argv[3] : 'http://127.0.0.1:5180';
const probe = process.argv.includes('--probe');
mkdirSync(out, { recursive: true });

const benchmark = await (await fetch(`${base}/api/benchmark`)).json();
const run = benchmark.cases.find((row) => row.key === 'A3')?.runIds[0];

/** Every visitor screen by its address; a window is checked inside the window. */
const SCREENS = [
  ['hook', '/'],
  ['e1-scene', '/try/attacker/scene'],
  ['e1-compare', '/try/attacker/compare'],
  ['e1-predict', '/try/attacker/predict'],
  ['e1-result', '/try/attacker/result'],
  ['e1-reason', '/try/attacker/reason'],
  ['e1-after', '/try/attacker/after'],
  ['e2-scene', '/try/owner/scene'],
  ['e2-compare', '/try/owner/compare'],
  ['e2-predict', '/try/owner/predict'],
  ['g-rules', '/intro/how/rules'],
  ['follow', '/try/follow'],
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
  ['glossary', '/?modal=glossary', 'dialog[open]'],
];

const browser = await chromium.launch();
const report = [];
for (const language of ['ko', 'en']) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    locale: language,
    reducedMotion: 'reduce',
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 300)));
  for (const [name, path, root = 'main'] of SCREENS) {
    await page.goto(`${base}${path}${path.includes('?') ? '&' : '?'}lng=${language}`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(600);
    if (probe) {
      await page.setViewportSize({ width: 390, height: 844 });
      await page.waitForTimeout(300);
      report.push({ language, name, width: 390, ...(await inspect(page, root)), phone: await mobile(page) });
      await page.setViewportSize({ width: 1440, height: 900 });
    } else {
      await capture(page, out, language, name, report, root);
    }
  }
  report.push({ language, name: 'errors', errors });
  await context.close();
}
await browser.close();

writeFileSync(join(out, 'report.json'), JSON.stringify(report, null, 2));
const problems = report.filter(
  (entry) =>
    entry.name !== 'errors' &&
    (entry.overflow > 0 ||
      entry.bandOverlap > 0 ||
      entry.singleLetter.length > 0 ||
      entry.serious.length > 0 ||
      (entry.limits &&
        (entry.limits.primaries > 1 ||
          entry.limits.numbers > 20 ||
          entry.limits.headlines !== 1 ||
          (entry.language === 'ko' && entry.limits.english.length > 0) ||
          (entry.language === 'en' && entry.limits.korean.length > 0))) ||
      (entry.phone &&
        (entry.phone.smallTextCount > 0 || entry.phone.smallTargetCount > 0 || entry.phone.mainFixed === false))),
);
console.log(`${report.length} entries, ${problems.length} with problems`);
for (const entry of problems) {
  console.log(
    JSON.stringify({
      language: entry.language,
      name: entry.name,
      width: entry.width,
      overflow: entry.overflow,
      bandOverlap: entry.bandOverlap,
      singleLetter: entry.singleLetter,
      serious: entry.serious.map((item) => item.id),
      limits: entry.limits && {
        ...entry.limits,
        english: entry.language === 'ko' ? entry.limits.english : [],
        korean: entry.language === 'en' ? entry.limits.korean : [],
      },
      phone: entry.phone,
    }),
  );
}
for (const entry of report.filter((item) => item.name === 'errors' && item.errors.length > 0)) {
  console.log(JSON.stringify(entry));
}
