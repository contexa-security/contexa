// 일회용: 휴대폰 폭에서 접는 줄과 에이전트 벤치마크 링크의 높이를 잽니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 390, height: 844 }, locale: 'ko-KR', reducedMotion: 'reduce' })).newPage();
for (const path of ['/attack/request', '/insider/reason', '/agent/request', '/agent/result']) {
  await page.goto(`http://127.0.0.1:5180${path}?lng=ko`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  const rows = await page.evaluate(() => [...document.querySelectorAll('summary, a[href="/benchmark/agent"]')].map((el) => { const r = el.getBoundingClientRect(); const marker = getComputedStyle(el).display; return `${el.tagName} ${Math.round(r.width)}x${Math.round(r.height)} display=${marker} "${el.textContent.trim().slice(0, 24)}"`; }));
  console.log(path, JSON.stringify(rows));
}
await browser.close();
