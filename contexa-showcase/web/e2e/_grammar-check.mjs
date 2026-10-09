// Temporary helper (to be deleted): the full screen check (C-3, C-4, C-5) of every act 1 and act 2 screen at the four
// widths in Korean and English, with the visitor states _prep-states.mjs kept, without sending new runs.
// Usage: node e2e/_grammar-check.mjs <state dir> <out dir>
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { capture } from './screenCheck.mjs';

const [stateDir, out] = process.argv.slice(2);
const base = process.env.SCREEN_BASE ?? 'http://127.0.0.1:5180';
mkdirSync(out, { recursive: true });

const SCREENS = {
  attacker: [
    ['hook', '/'],
    ['e1-scene', '/try/attacker/scene'],
    ['e1-compare', '/try/attacker/compare'],
    ['e1-predict', '/try/attacker/predict'],
    ['e1-run', '/try/attacker/run'],
    ['e1-result', '/try/attacker/result'],
    ['e1-reason', '/try/attacker/reason'],
    ['e1-after', '/try/attacker/after'],
    ['e1-end', '/try/attacker/end'],
  ],
  owner: [
    ['e2-scene', '/try/owner/scene'],
    ['e2-compare', '/try/owner/compare'],
    ['e2-predict', '/try/owner/predict'],
    ['e2-run', '/try/owner/run'],
    ['e2-result', '/try/owner/result'],
    ['e2-reason', '/try/owner/reason'],
    ['g-rules', '/intro/how/rules'],
    ['e2-check', '/try/owner/after'],
    ['follow', '/try/follow'],
    ['e2-end', '/try/follow/end'],
  ],
  act3: [
    ['learn-why', '/intro/learning'],
    ['learned', '/intro/learning/learned'],
    ['g-how', '/intro/how'],
    ['prompt', '/try/prompt'],
    ['t1', '/try/timing/concept'],
    ['t2', '/try/timing/try'],
    ['t3', '/try/timing/compare'],
    ['t4', '/try/timing/when'],
    ['stack', '/try/stack'],
    ['learn-after', '/try/summary/learning'],
    ['e3-end', '/try/summary/learning/end'],
  ],
};
const ONLY = process.argv[4] ? new Set(process.argv[4].split(',')) : null;
const NAMES = process.argv[5] ? new Set(process.argv[5].split(',')) : null;

const browser = await chromium.launch();
const report = [];
for (const language of ['ko', 'en']) {
  for (const role of ['attacker', 'owner', 'act3']) {
    if (ONLY && !ONLY.has(role)) continue;
    const context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      locale: language,
      reducedMotion: 'reduce',
      storageState: join(stateDir, `state-${role}.json`),
    });
    const page = await context.newPage();
    for (const [name, path] of SCREENS[role]) {
      if (NAMES && !NAMES.has(name)) continue;
      await page.goto(`${base}${path}?lng=${language}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(name === 'hook' ? 9000 : 900);
      await capture(page, out, language, name, report);
    }
    await context.close();
  }
}
await browser.close();
writeFileSync(join(out, 'report.json'), JSON.stringify(report, null, 2));
const problems = report.filter(
  (row) =>
    row.overflow > 0 ||
    row.singleLetter.length > 0 ||
    row.serious.length > 0 ||
    (row.limits && (row.limits.primaries !== 1 || row.limits.numbers > 20)) ||
    (row.language === 'ko' && row.limits && row.limits.english.length > 0),
);
for (const row of problems) {
  console.log(
    `${row.name} ${row.language} ${row.width}: overflow=${row.overflow} single=${JSON.stringify(row.singleLetter)} serious=${JSON.stringify(row.serious)} primaries=${row.limits?.primaries} numbers=${row.limits?.numbers} english=${JSON.stringify(row.limits?.english)}`,
  );
}
console.log(`${report.length} captures, ${problems.length} with something to look at`);
