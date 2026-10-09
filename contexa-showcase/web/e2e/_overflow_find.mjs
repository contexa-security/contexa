import { chromium } from '@playwright/test';
const [language, width, path] = [process.argv[2], Number(process.argv[3]), process.argv[4] ?? '/design/parts'];
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width, height: 900 }, locale: language });
const page = await context.newPage();
await page.goto(`http://127.0.0.1:5180${path}?lng=${language}`, { waitUntil: 'networkidle' });
const found = await page.evaluate(() => {
  const limit = document.documentElement.clientWidth;
  const out = [];
  for (const element of document.querySelectorAll('body *')) {
    const rect = element.getBoundingClientRect();
    if (rect.right > limit + 0.5 && rect.width > 0) {
      out.push(`${element.tagName.toLowerCase()}.${String(element.className).slice(0, 60)} right=${Math.round(rect.right)} w=${Math.round(rect.width)} text=${(element.textContent ?? '').trim().slice(0, 40)}`);
    }
  }
  return out.slice(0, 30);
});
console.log(found.join('\n'));
await browser.close();
