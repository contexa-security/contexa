// P7 C-24 stand-in (화면설계-프롬프트신뢰-보강안 6; the user decided on 2026-10-09 that no first-visitor test is run, and
// C-1 was closed by the same kind of screen check, S12-검수 C-1): whether '/try/prompt' alone answers "what did the AI
// receive and where did it come from". At 1440 x 900 and 390 x 844 in ko and en, the purpose sentence and the names of
// the five parts (what it received) must be visible, and at least one source chip (where it came from). A person's
// understanding is not measured here; this only shows the answer is on screen.
// Usage: node e2e/p7-c24-proxy.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:19180';
mkdirSync(out, { recursive: true });

const PATH = '/try/prompt';
const KEYS = [
  'prompt.purpose',
  'prompt.block.REQUEST',
  'prompt.block.SESSION',
  'prompt.block.USER_BASELINE',
  'prompt.block.DECISION_FACTS',
  'prompt.block.UNKNOWN',
];

// True when any innermost element holding the words is visible (a hidden copy of the words, such as a visually hidden
// label, does not decide it).
function visibleText(words) {
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
  let node = walker.currentNode;
  while (node) {
    const element = node;
    const text = (element.textContent ?? '').replace(/\s+/g, ' ').trim();
    if (text.includes(words) && [...element.children].every((child) => !(child.textContent ?? '').replace(/\s+/g, ' ').includes(words))) {
      const box = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      if (box.width > 0 && box.height > 0 && style.visibility !== 'hidden') {
        return true;
      }
    }
    node = walker.nextNode();
  }
  return false;
}

const browser = await chromium.launch();
const report = [];
for (const language of ['ko', 'en']) {
  const m = JSON.parse(readFileSync(`src/i18n/${language}.json`, 'utf-8'));
  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
    const page = await browser.newPage({ viewport, locale: language, reducedMotion: 'reduce' });
    await page.goto(`${base}${PATH}?lng=${language}`, { waitUntil: 'networkidle' });
    await page.locator('main h1').first().waitFor();
    await page.waitForTimeout(800);
    const missing = [];
    for (const key of KEYS) {
      const words = (m[key] ?? '').replace(/\s+/g, ' ').trim();
      if (!words || !(await page.evaluate(visibleText, words))) {
        missing.push(key);
      }
    }
    // The source chips by their element (SourceChip: data-source), not by their words, which other text can contain.
    const chips = await page.evaluate(() => [...new Set([...document.querySelectorAll('[data-source]')]
      .filter((element) => {
        const box = element.getBoundingClientRect();
        return box.width > 0 && box.height > 0 && getComputedStyle(element).visibility !== 'hidden';
      })
      .map((element) => element.getAttribute('data-source')))]);
    if (chips.length === 0) {
      missing.push('fact.source.*');
    }
    report.push({ language, width: viewport.width, path: PATH, missing, sourceChips: chips });
    console.log(`${language} ${viewport.width} ${missing.length === 0 ? 'answered' : `missing ${missing.join(', ')}`} chips ${chips.join(',')}`);
    await page.screenshot({ path: join(out, `C24-${language}-${viewport.width}.png`) });
    await page.close();
  }
}
writeFileSync(join(out, 'c24-proxy.json'), JSON.stringify({ path: PATH, keys: KEYS, report }, null, 2));
await browser.close();
