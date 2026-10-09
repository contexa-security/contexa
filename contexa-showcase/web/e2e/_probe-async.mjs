// Temporary helper (to be deleted): sends the asynchronous attack from the "send it again" screen and prints the live
// run's state every two seconds, to see where a two-request asynchronous run waits.
import { chromium } from '@playwright/test';

const browser = await chromium.launch();
const context = await browser.newContext({ locale: 'ko' });
const page = await context.newPage();
await page.goto('http://127.0.0.1:5180/try/timing/try?lng=ko', { waitUntil: 'networkidle' });
await page.getByRole('button', { name: '같은 공격 비동기식으로 다시 보내기' }).click();
await page.waitForURL(/\/try\/attacker\/run/);
console.log('url', page.url(), 'lang', await page.evaluate(() => document.documentElement.lang));
for (let i = 0; i < 60; i += 1) {
  const run = await page.evaluate(() => fetch('/api/live/runs/current').then((r) => r.json()));
  console.log(
    i * 2,
    run.status,
    'awaiting',
    run.awaitingStep,
    'challenge',
    run.challenge?.stage,
    'steps',
    run.steps.map((step) => `${step.stepNo}:${Object.keys(step.layers).join('')}`).join(' '),
  );
  if (['COMPLETED', 'FAILED', 'EXPIRED'].includes(run.status)) break;
  const next = page.getByRole('button', { name: /다음 요청 보내기/ });
  if (await next.count()) await next.first().click();
  await page.waitForTimeout(2000);
}
const current = await page.evaluate(() => fetch('/api/live/runs/current').then((r) => r.json()));
console.log('current', current.scenario, current.status, current.runId);
const journey = await page.evaluate(() => fetch('/api/journey').then((r) => r.json()));
console.log('journey runs', JSON.stringify(journey.runs.map((line) => [line.scenarioKey, line.status, line.runId])));
await page.getByRole('link', { name: /두 실행 나란히 보기/ }).click();
await page.waitForURL(/\/try\/timing\/try/);
for (const wait of [500, 3000, 10000]) {
  await page.waitForTimeout(wait);
  const text = await page.locator('main').innerText();
  console.log('after', wait, text.includes('아직 보내지 않았습니다') ? 'EMPTY' : 'FILLED', text.match(/[0-9,]+건 나감/g));
}
const buttons = await page.getByRole('button').allInnerTexts();
console.log('buttons', buttons.filter((text) => text.trim()).slice(0, 12));
await browser.close();
