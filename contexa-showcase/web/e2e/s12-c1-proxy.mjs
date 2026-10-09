// S12 C-1 stand-in (plan 15.3 "시험자 지정"): until the user names a tester, whether the screens alone answer the five
// questions of the first-visitor test (screen design qa 1). For each question the screen it follows is opened at 1440 x
// 900 and 390 x 844, and the words that answer it must be visible there; for the five-second question, inside the first
// view without scrolling. A person's understanding is not measured here; this only shows the answer is on screen.
// Usage: node e2e/s12-c1-proxy.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:19180';
mkdirSync(out, { recursive: true });

const QUESTIONS = [
  {
    id: 'Q1',
    question: '무엇을 보여 주는 데모인가요? (시작 5초 뒤)',
    path: '/',
    keys: ['identity.line', 'hook.title'],
    firstView: true,
  },
  {
    id: 'Q2',
    question: 'Contexa는 판단할 때 무엇을 보나요? (판단 방식 뒤)',
    path: '/intro/how',
    keys: ['inside.cell.usual', 'inside.cell.company', 'inside.cell.history', 'how.new.text'],
  },
  {
    id: 'Q3',
    question: '체험 1의 사람은 누구이고 정답은? (진행 순서 뒤)',
    path: '/intro/order?route=intro',
    keys: ['order.try1.who', 'order.stolen', 'order.answer.stop'],
  },
  {
    id: 'Q4',
    question: '동기식과 비동기식은 언제 쓰나요? (체험 뒤)',
    path: '/try/timing/when',
    keys: ['timing.when.q1', 'timing.when.syncFits', 'timing.when.syncWork', 'timing.when.asyncFits', 'timing.when.asyncWork'],
  },
  {
    id: 'Q5',
    question: '기존 보안과 무엇이 다른가요? (정리 뒤)',
    path: '/try/summary/recap',
    keys: ['identity.definition', 'difference.1', 'difference.2', 'difference.3', 'difference.4', 'difference.5', 'difference.6'],
  },
];

const browser = await chromium.launch();
const report = [];
for (const language of ['ko', 'en']) {
  const m = JSON.parse(readFileSync(`src/i18n/${language}.json`, 'utf-8'));
  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
    const page = await browser.newPage({ viewport, locale: language, reducedMotion: 'reduce' });
    for (const item of QUESTIONS) {
      await page.goto(`${base}${item.path}${item.path.includes('?') ? '&' : '?'}lng=${language}`, {
        waitUntil: 'networkidle',
      });
      await page.locator('main h1').first().waitFor();
      await page.waitForTimeout(800);
      const missing = [];
      for (const key of item.keys) {
        const words = (m[key] ?? '').replace(/\s+/g, ' ').trim();
        const shown = await page.evaluate(
          ({ words, firstView }) => {
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
            let node = walker.currentNode;
            while (node) {
              const element = node;
              const text = (element.textContent ?? '').replace(/\s+/g, ' ').trim();
              if (text.includes(words) && [...element.children].every((child) => !(child.textContent ?? '').replace(/\s+/g, ' ').includes(words))) {
                const box = element.getBoundingClientRect();
                const style = getComputedStyle(element);
                const visible = box.width > 0 && box.height > 0 && style.visibility !== 'hidden';
                return visible && (!firstView || box.top < window.innerHeight);
              }
              node = walker.nextNode();
            }
            return false;
          },
          { words, firstView: item.firstView === true },
        );
        if (!shown) {
          missing.push(key);
        }
      }
      report.push({ language, width: viewport.width, id: item.id, path: item.path, missing });
      console.log(`${language} ${viewport.width} ${item.id} ${missing.length === 0 ? 'answered' : `missing ${missing.join(', ')}`}`);
      await page.screenshot({ path: join(out, `${item.id}-${language}-${viewport.width}.png`) });
    }
    await page.close();
  }
}
writeFileSync(join(out, 'c1-proxy.json'), JSON.stringify({ questions: QUESTIONS, report }, null, 2));
await browser.close();
