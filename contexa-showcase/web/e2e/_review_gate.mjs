// 일회용: 포털의 실행 시작 문이 어떤 상태·사유로 답하는지 봅니다(방문자 한 명이 공격 사례를 보내 봄). 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';

const base = process.env.BASE ?? 'http://127.0.0.1:19180';
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR', reducedMotion: 'reduce' });
const page = await context.newPage();
page.on('response', async (response) => {
  if (response.url().includes('/api/live/runs') && response.request().method() === 'POST') {
    const text = await response.text().catch(() => '');
    console.log('POST /api/live/runs', response.status(), text.slice(0, 300));
  }
});
await page.goto(`${base}/attack/request?lng=ko`, { waitUntil: 'networkidle' });
await page.getByText('차단된다', { exact: false }).first().click();
await page.locator('[data-zone="actions"] [data-main]').click();
await page.waitForTimeout(6000);
console.log('url', page.url());
const alert = await page.locator('[role="alert"]').allTextContents();
console.log('alert', JSON.stringify(alert));
const stats = await page.evaluate(() => fetch('/api/live/config').then((r) => r.text()).catch(() => ''));
console.log('config', stats.slice(0, 400));
await browser.close();
