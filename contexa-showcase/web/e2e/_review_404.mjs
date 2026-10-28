// 일회용: 404를 내는 요청 주소를 찾습니다(코드 변경 없음). 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR' });
const page = await context.newPage();
const bad = [];
page.on('response', (r) => { if (r.status() >= 400) bad.push(`${r.status()} ${r.request().method()} ${r.url()}`); });
for (const path of ['/attack/request', '/agent/request', '/benchmark']) {
  bad.length = 0;
  await page.goto(`http://127.0.0.1:19180${path}?lng=ko`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(800);
  console.log(path, JSON.stringify(bad));
}
await browser.close();
