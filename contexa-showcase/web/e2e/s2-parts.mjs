// S2 check (C-4, C-8 part): the shared components on /design/parts at 390, 768, 1024 and 1440 px in Korean and English:
// no horizontal overflow, no single-letter wrapping in headings and buttons, and no serious or critical axe violation.
// Usage: node e2e/s2-parts.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:5180';
mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
const report = [];
for (const language of ['ko', 'en']) {
  for (const width of [390, 768, 1024, 1440]) {
    const context = await browser.newContext({ viewport: { width, height: 900 }, locale: language });
    const page = await context.newPage();
    await page.goto(`${base}/design/parts?lng=${language}`, { waitUntil: 'networkidle' });
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    // A text that wraps and leaves one letter alone on its last line; short boxes on one line (a step number next to
    // its label) are not wrapping and are not counted.
    const singleLetter = await page.evaluate(() => {
      const found = [];
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      const range = document.createRange();
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        const text = node.textContent ?? '';
        if (text.trim().length < 2 || node.parentElement?.closest('[aria-hidden="true"], .sr-only')) continue;
        const tops = (from, to) => {
          range.setStart(node, from);
          range.setEnd(node, to);
          return [...range.getClientRects()]
            .filter((rect) => rect.width > 0)
            .map((rect) => Math.round(rect.top));
        };
        const lines = new Set(tops(0, text.length));
        if (lines.size < 2) continue;
        const last = Math.max(...lines);
        let letters = 0;
        for (let i = text.length - 1; i >= 0; i -= 1) {
          if (/\s/.test(text[i] ?? '')) continue;
          if (Math.max(...tops(i, i + 1)) !== last) break;
          if (/[\p{L}\p{N}]/u.test(text[i] ?? '')) letters += 1;
        }
        if (letters === 1) found.push(text.trim().slice(0, 40));
      }
      return found;
    });
    const axe = await new AxeBuilder({ page }).analyze();
    const serious = axe.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
    await page.screenshot({ path: join(out, `parts-${language}-${width}.png`), fullPage: true });
    report.push({
      language,
      width,
      overflow,
      singleLetter,
      serious: serious.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 3) })),
    });
    await context.close();
  }
}
// C-7 and C-8 on the shared modal (common-2): opened from the middle of the page and closed by Esc, the browser's back
// button or its close button, the page stays where it was, the address loses ?modal= and the focus returns to the
// opener; the open modal passes axe too. Closing by a click outside is the fourth way.
const modals = [];
for (const width of [1440, 390]) {
  const context = await browser.newContext({ viewport: { width, height: 900 }, locale: 'ko' });
  const page = await context.newPage();
  await page.goto(`${base}/design/parts?lng=ko`, { waitUntil: 'networkidle' });
  const badge = page.getByRole('button', { name: /확인한 차이/ }).first();
  for (const close of ['escape', 'back', 'button', 'outside']) {
    await page.evaluate(() => window.scrollTo(0, 200));
    const before = await page.evaluate(() => window.scrollY);
    await badge.evaluate((element) => element.focus({ preventScroll: true }));
    await page.keyboard.press('Enter');
    await page.getByRole('dialog').waitFor();
    const opened = new URL(page.url()).searchParams.get('modal');
    const titleFocused = await page.evaluate(
      () => document.activeElement?.hasAttribute('data-modal-title') ?? false,
    );
    const axe = await new AxeBuilder({ page }).include('dialog').analyze();
    const serious = axe.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').length;
    if (close === 'escape') {
      await page.keyboard.press('Escape');
    } else if (close === 'back') {
      await page.goBack();
    } else if (close === 'button') {
      await page.getByRole('dialog').getByRole('button', { name: '닫기' }).click();
    } else {
      await page.mouse.click(4, 4);
    }
    await page.getByRole('dialog').waitFor({ state: 'hidden' });
    modals.push({
      width,
      close,
      opened,
      titleFocused,
      serious,
      address: new URL(page.url()).search,
      before,
      after: await page.evaluate(() => window.scrollY),
      focusBack: await page.evaluate(() => document.activeElement?.textContent ?? ''),
    });
  }
  await context.close();
}
await browser.close();
writeFileSync(join(out, 'parts-report.json'), JSON.stringify({ report, modals }, null, 1));
for (const row of report) {
  console.log(
    `${row.language} ${row.width}: overflow ${row.overflow}, single-letter ${row.singleLetter.length}, axe serious ${row.serious.length}`,
  );
}
for (const row of modals) {
  console.log(
    `modal ${row.width} ${row.close}: opened ?modal=${row.opened}, title focused ${row.titleFocused}, axe serious ${row.serious}, address after "${row.address}", scroll ${row.before} -> ${row.after}, focus back on "${row.focusBack}"`,
  );
}
