// 일회용: 영어 6-2(에이전트 콘솔)가 실제 실행 뒤 옆으로 넘치는지, 무엇이 넘치는지 잽니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';

const base = process.env.BASE ?? 'http://127.0.0.1:19180';
const width = Number(process.env.W ?? 1280);
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width, height: 720 }, locale: 'en-US', reducedMotion: 'reduce' });
const page = await context.newPage();
await page.goto(`${base}/agent/request?lng=en`, { waitUntil: 'networkidle' });
await page.getByText('It is stopped', { exact: true }).click();
await page.locator('[data-zone="actions"] [data-main]').click();
await page.waitForURL(/\/agent\/console/);
await page.locator('[data-zone="actions"] [data-main]').filter({ hasText: /See the result/ }).waitFor({ timeout: 420000 });
await page.waitForTimeout(1500);
const report = await page.evaluate(() => {
  const root = document.documentElement;
  const wide = [];
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width > 0 && r.right > window.innerWidth + 1) {
      wide.push({ tag: el.tagName, cls: String(el.className).slice(0, 60), right: Math.round(r.right), width: Math.round(r.width), text: (el.textContent ?? '').trim().slice(0, 70) });
    }
  }
  const header = document.querySelector('header');
  const parts = header
    ? [...header.querySelectorAll(':scope > div > *, :scope > div > div > *, :scope > *')].map((e) => {
        const r = e.getBoundingClientRect();
        return `${e.tagName}.${String(e.className).slice(0, 24)} ${Math.round(r.left)}-${Math.round(r.right)} w${Math.round(r.width)} "${(e.textContent ?? '').trim().slice(0, 50)}"`;
      })
    : [];
  const hb = header ? header.getBoundingClientRect() : null;
  return { scrollWidth: root.scrollWidth, inner: window.innerWidth, headerRight: hb ? Math.round(hb.right) : null, parts, wide: wide.filter((w) => w.tag === 'TABLE' || w.tag === 'DIV').slice(0, 6) };
});
console.log(JSON.stringify(report, null, 1));
await page.screenshot({ path: process.argv[2] ?? 'overflow6.png', fullPage: true });
await browser.close();
