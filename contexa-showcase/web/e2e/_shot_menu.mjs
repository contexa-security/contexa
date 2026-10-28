// Disposable: screenshots of /lab/agent with the agent menu, to look at the layout (the user may delete it).
import path from 'node:path';
import { chromium } from '@playwright/test';

const out = process.argv[2];
const browser = await chromium.launch();
for (const width of [1440, 390]) {
  const context = await browser.newContext({ locale: 'ko-KR', viewport: { width, height: width === 390 ? 844 : 1000 } });
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:19180/lab/agent?lng=ko', { waitUntil: 'networkidle' });
  await page.getByRole('radiogroup', { name: '사례' }).waitFor({ timeout: 15000 });
  await page.getByRole('region', { name: '고른 조합의 저장된 결과' }).getByRole('button', { name: '예상 없이 바로 보기' }).click();
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(out, `menu-${width}.png`), fullPage: true });
  await context.close();
}
await browser.close();
