// Temporary helper (to be deleted): sends try 3 as a new visitor, waits for the meter, and keeps that visitor's state,
// so the act 3 screens can be captured with a visitor's own try 3 without changing the other kept visitors.
// Usage: node e2e/_prep-stack.mjs <state dir>
import { chromium } from '@playwright/test';
import { join } from 'node:path';

const stateDir = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:5180';
const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  locale: 'ko',
});
const page = await context.newPage();
await page.goto(`${base}/try/stack?lng=ko`, { waitUntil: 'networkidle' });
await page.getByRole('button', { name: '다섯 번 조회 보내기' }).click();
await page.locator('main table tbody tr').nth(4).waitFor({ timeout: 300_000 });
console.log('meter rows', await page.locator('main table tbody tr').count());
await context.storageState({ path: join(stateDir, 'state-act3.json') });
await browser.close();
