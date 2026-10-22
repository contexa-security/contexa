// 판정층 8절 9 check on the real stack: one real run of the streamed export A3S from the lab, in Korean. The live bars
// are captured while the stream is read and after it ended (Contexa's line names where its block cut the stream when
// the engine blocked), then the result and the decision details' summary (a cut block applies while it is sent).
// One run calls the Layer1 model once or twice; Layer2 only when Layer1 escalates on its own.
// Usage: node e2e/cut-scene.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:19180';
const m = JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8'));
mkdirSync(out, { recursive: true });
const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  locale: 'ko',
  reducedMotion: 'reduce',
});
const page = await context.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(String(e).slice(0, 300)));
const bars = async () =>
  page
    .locator('[data-control]')
    .evaluateAll((items) =>
      items.map((item) => ({ control: item.getAttribute('data-control'), text: item.textContent })),
    );
const shots = [];

await page.goto(`${base}/lab/send?case=A3S&lng=ko`, { waitUntil: 'networkidle' });
await page
  .locator('label')
  .filter({ has: page.getByRole('radio', { name: new RegExp(escape(m['lab.r7.send.call.ATTACK'])) }) })
  .click();
await page.getByRole('button', { name: m['lab.r7.send.send'] }).click();
await page.waitForURL(/sent=/, { timeout: 60_000 });
const started = Date.now();
for (const at of [4_000, 9_000, 20_000]) {
  await page.waitForTimeout(Math.max(0, at - (Date.now() - started)));
  await page.screenshot({ path: join(out, `cut-${at / 1000}s.png`), fullPage: true });
  shots.push({ at, bars: await bars() });
}
await page.getByRole('link', { name: m['lab.r7.run.next'] }).waitFor({ timeout: 300_000 });
await page.screenshot({ path: join(out, 'cut-end.png'), fullPage: true });
shots.push({ at: 'end', bars: await bars(), url: page.url() });
await page.getByRole('link', { name: m['lab.r7.run.next'] }).click();
await page.waitForURL(/\/lab\/result/);
await page.waitForTimeout(1500);
await page.screenshot({ path: join(out, 'cut-result.png'), fullPage: true });
const result = { url: page.url(), text: (await page.locator('main').innerText()).slice(0, 3000) };
writeFileSync(join(out, 'cut-report.json'), JSON.stringify({ shots, result, errors }, null, 1));
console.log(JSON.stringify({ shots, resultUrl: result.url, errors }, null, 1));
await browser.close();
