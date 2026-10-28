// docs/agent Agent중심-화면 AC-5 (3), G-5: the people's recorded replays (the pairs A1, A3, A5, A6, A8) work as before: each
// replay screen opens in a real browser on the running portal with its recorded decisions, no error state, no script
// error, and the page sends nothing but reads. READ ONLY.
// Usage (web folder): node e2e/s2-replay-check.mjs <outDir> [--base http://127.0.0.1:19180]
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s2-replay-check.mjs <outDir> [--base <url>]');
  process.exit(2);
}
const baseAt = args.indexOf('--base');
const base = baseAt >= 0 ? args[baseAt + 1] : 'http://127.0.0.1:19180';
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [] };
function check(name, ok, detail = '') {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

const browser = await chromium.launch();
try {
  for (const width of [1440, 390]) {
    const context = await browser.newContext({ locale: 'ko-KR', viewport: { width, height: width === 390 ? 844 : 1000 } });
    const page = await context.newPage();
    const errors = [];
    const writes = [];
    page.on('pageerror', (error) => errors.push(String(error)));
    page.on('request', (request) => {
      if (request.method() !== 'GET') {
        writes.push(`${request.method()} ${request.url().slice(base.length)}`);
      }
    });
    const pairs = await (await page.request.get(`${base}/api/pairs`)).json();
    const keys = pairs.map((pair) => pair.key ?? pair.pairKey);
    const recorded = new Set(pairs.filter((pair) => pair.recorded).map((pair) => pair.key));
    check(`[${width}px] the pairs are the five of the people's replays`, keys.join() === 'A1,A3,A5,A6,A8', keys.join());
    for (const key of keys) {
      const replay = await page.request.get(`${base}/api/replays/${key}`);
      // A pair without a published recording answers 404 and the screen says so; a recorded one is served.
      check(`[${width}px] ${key}: ${recorded.has(key) ? 'the recorded replay is served' : 'no recording is published, as /api/pairs says'}`,
        replay.status() === (recorded.has(key) ? 200 : 404), String(replay.status()));
      await page.goto(`${base}/replay/${key}?lng=ko`, { waitUntil: 'networkidle' });
      const text = await page.locator('main').innerText();
      check(`[${width}px] ${key}: the replay screen shows its record`, text.length > 200 && !/기술 문제|찾을 수 없/.test(text),
        `${text.length} characters`);
      if (width === 1440) {
        await page.screenshot({ path: path.join(out, `replay-${key}.png`), fullPage: true });
      }
    }
    check(`[${width}px] the replay screens sent nothing but reads and the journey position`,
      writes.every((write) => write === 'POST /api/journey'), JSON.stringify(writes.slice(0, 4)));
    check(`[${width}px] no script error`, errors.length === 0, errors.slice(0, 2).join(' | '));
    await context.close();
  }
} finally {
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
console.log(report.failures.length === 0 ? 'ALL PASS' : `FAILED: ${report.failures.join('; ')}`);
process.exit(report.failures.length === 0 ? 0 : 1);
