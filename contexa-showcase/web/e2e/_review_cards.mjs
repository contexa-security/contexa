import { chromium } from '@playwright/test';

const base = 'http://127.0.0.1:19180';
const screens = [
  ['1-1', '/'],
  ['C-1', '/choose'],
  ['H-1', '/person'],
  ['H-6', '/person/next'],
  ['A-1', '/agent'],
  ['A-6', '/agent/next'],
  ['D-1', '/deeper'],
];
const browser = await chromium.launch();
for (const [width, height] of [[1440, 900], [390, 844]]) {
  const context = await browser.newContext({ viewport: { width, height }, locale: 'ko-KR', reducedMotion: 'reduce' });
  const page = await context.newPage();
  for (const [name, path] of screens) {
    await page.goto(`${base}${path}?lng=ko`, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(400);
    const out = await page.evaluate(() => {
      const visible = (el) => {
        for (let d = el.closest('details:not([open])'); d; d = d.parentElement?.closest('details:not([open])') ?? null) {
          const s = el.closest('summary');
          if (!(s && s.parentElement === d)) return false;
        }
        return true;
      };
      const cards = [...document.querySelectorAll('[data-choice]')];
      const shown = cards.filter(visible);
      const fold = document.querySelector('details[data-fold="choose-more"]');
      return { cards: cards.length, shown: shown.length, fold: fold ? fold.querySelectorAll('[data-choice]').length : 0 };
    });
    console.log(width, name, JSON.stringify(out));
  }
  await context.close();
}
await browser.close();
