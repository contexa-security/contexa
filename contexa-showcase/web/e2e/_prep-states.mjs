// Temporary helper (to be deleted): sends one live run of try 1 and one of try 2 as one visitor and keeps the
// browser state after each, so the screens can be captured again and again without sending more runs.
// Usage: node e2e/_prep-states.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:5180';
const m = JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8'));
mkdirSync(out, { recursive: true });
const format = (template, values) => template.replace(/\{\{(\w+)\}\}/g, (_, key) => String(values[key] ?? ''));
const api = (page, path) => page.evaluate((p) => fetch(p).then((r) => (r.ok ? r.json() : null)), path);

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko' });
const page = await context.newPage();

async function send(role, caseKey, pick) {
  await page.goto(`${base}/try/${role}/predict?lng=ko`, { waitUntil: 'networkidle' });
  await pick();
  const options = await api(page, '/api/lab/options');
  const items = options.cases.find((c) => c.key === caseKey).requests[0].items;
  await page.getByRole('button', { name: format(m['e1.predict.send'], { items: items.toLocaleString('ko-KR') }) }).click();
  await page.waitForURL(new RegExp(`/try/${role}/run`));
  const next = page.getByRole('link', { name: m['e1.next.result'] });
  const deadline = Date.now() + 240_000;
  while (Date.now() < deadline && !(await next.count())) {
    const request = page.getByRole('button', { name: m['try.challenge.requestCode'] });
    if (await request.count()) {
      await request.click();
    }
    const use = page.getByRole('button', { name: m['try.challenge.useCode'] });
    if (await use.count()) {
      await use.click();
    }
    await page.waitForTimeout(1000);
  }
  console.log(role, (await next.count()) ? 'done' : 'timed out');
}

const only = process.argv[4] ?? 'both';
if (only !== 'owner') {
  await send('attacker', 'A3', async () => {
    await page.getByText(m['e1.predict.CHALLENGE'], { exact: true }).first().click();
  });
  await context.storageState({ path: join(out, 'state-attacker.json') });
}
if (only === 'attacker') {
  await browser.close();
  process.exit(0);
}
await send('owner', 'A3T', async () => {
  await page.getByText(m['e1.predict.ALLOW'], { exact: true }).first().click();
  await page
    .locator('fieldset', { hasText: m['e2.predict.numberRule'] })
    .getByText(m['e2.predict.numberRule.STOP'], { exact: true })
    .click();
});
await context.storageState({ path: join(out, 'state-owner.json') });
await browser.close();
