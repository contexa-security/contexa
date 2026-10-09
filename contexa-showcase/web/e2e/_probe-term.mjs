import { chromium } from '@playwright/test';
const browser = await chromium.launch();
const page = await browser.newPage();
await page.goto('http://127.0.0.1:5180/intro/concept?route=intro&lng=ko', { waitUntil: 'networkidle' });
const html = await page.evaluate(() => {
  const button = [...document.querySelectorAll('main button')].find((b) => b.textContent === '로그인 상태');
  const wrap = button?.parentElement;
  const s = getComputedStyle(button);
  return { parent: wrap?.parentElement?.outerHTML.slice(0, 700), margin: s.margin, padding: s.padding, display: s.display, wrapDisplay: getComputedStyle(wrap).display, wrapMargin: getComputedStyle(wrap).margin };
});
console.log(JSON.stringify(html, null, 1));
await browser.close();
