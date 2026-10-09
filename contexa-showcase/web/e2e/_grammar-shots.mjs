// Temporary helper (to be deleted): captures the screens of acts 1 and 2 with the visitor states _prep-states.mjs
// kept, at the given widths, full page, and reports horizontal overflow and page errors per capture.
// Usage: node e2e/_grammar-shots.mjs <state dir> <out dir> <widths comma separated> [language] [only names comma separated]
import { chromium } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

const [stateDir, out, widthList, language = 'ko', onlyList = ''] = process.argv.slice(2);
const base = process.env.SCREEN_BASE ?? 'http://127.0.0.1:5180';
const widths = widthList.split(',').map(Number);
const only = onlyList ? new Set(onlyList.split(',')) : null;
mkdirSync(out, { recursive: true });

const SCREENS = [
  ['attacker', 'hook', '/'],
  ['attacker', 'e1-scene', '/try/attacker/scene'],
  ['attacker', 'e1-compare', '/try/attacker/compare'],
  ['attacker', 'e1-predict', '/try/attacker/predict'],
  ['attacker', 'e1-run', '/try/attacker/run'],
  ['attacker', 'e1-result', '/try/attacker/result'],
  ['attacker', 'e1-reason', '/try/attacker/reason'],
  ['attacker', 'e1-after', '/try/attacker/after'],
  ['attacker', 'e1-end', '/try/attacker/end'],
  ['owner', 'e2-scene', '/try/owner/scene'],
  ['owner', 'e2-compare', '/try/owner/compare'],
  ['owner', 'e2-predict', '/try/owner/predict'],
  ['owner', 'e2-run', '/try/owner/run'],
  ['owner', 'e2-result', '/try/owner/result'],
  ['owner', 'e2-reason', '/try/owner/reason'],
  ['owner', 'g-rules', '/intro/how/rules'],
  ['owner', 'e2-check', '/try/owner/after'],
  ['owner', 'follow', '/try/follow'],
  ['owner', 'e2-end', '/try/follow/end'],
  ['owner', 'learn-why', '/intro/learning'],
  ['owner', 'learned', '/intro/learning/learned'],
  ['owner', 'g-how', '/intro/how'],
  ['owner', 'prompt', '/try/prompt'],
  ['owner', 't1', '/try/timing/concept'],
  ['owner', 't2', '/try/timing/try'],
  ['owner', 't3', '/try/timing/compare'],
  ['owner', 't4', '/try/timing/when'],
  ['owner', 'stack', '/try/stack'],
  ['owner', 'learn-after', '/try/summary/learning'],
  ['owner', 'e3-end', '/try/summary/learning/end'],
];

const browser = await chromium.launch();
for (const role of ['attacker', 'owner']) {
  for (const width of widths) {
    const context = await browser.newContext({
      viewport: { width, height: 900 },
      locale: language,
      reducedMotion: 'reduce',
      storageState: join(stateDir, `state-${role}.json`),
    });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(String(e).slice(0, 300)));
    for (const [owner, name, path] of SCREENS) {
      if (owner !== role || (only && !only.has(name))) {
        continue;
      }
      errors.length = 0;
      await page.goto(`${base}${path}?lng=${language}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(name === 'hook' ? 9000 : 900);
      const file = join(out, `${name}-${language}-${width}.png`);
      await page.screenshot({ path: file, fullPage: true });
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
      console.log(`${name} ${width} overflow=${overflow} errors=${errors.length ? errors.join(' | ') : 0}`);
    }
    await context.close();
  }
}
await browser.close();
