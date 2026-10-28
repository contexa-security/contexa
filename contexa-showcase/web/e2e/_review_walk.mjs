// 일회용: 새 흐름(사람 갈래와 에이전트 갈래)을 개발 서버에서 한 번씩 걸어 보며 화면을 찍고 글자 수를 잽니다. 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const base = process.env.BASE ?? 'http://127.0.0.1:5180';
const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch();

async function viewportChars(page) {
  return page.evaluate(() => {
    const vh = window.innerHeight;
    let chars = 0;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = n.textContent.replace(/\s+/g, '');
      if (!text) continue;
      const el = n.parentElement;
      if (!el || el.closest('script,style,noscript,header[data-zone="top"]')) continue;
      const r = document.createRange();
      r.selectNodeContents(n);
      const b = r.getBoundingClientRect();
      if (b.width === 0 || b.top >= vh || b.bottom <= 0) continue;
      chars += text.length;
    }
    return chars;
  });
}

for (const [tag, width, height] of [['d', 1440, 900], ['m', 390, 844]]) {
  const context = await browser.newContext({ viewport: { width, height }, locale: 'ko-KR', reducedMotion: 'reduce' });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 200)));
  const log = [];
  async function shot(name) {
    await page.waitForTimeout(700);
    const chars = await viewportChars(page);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    await page.screenshot({ path: `${out}/${tag}-${name}.png` });
    log.push(`${tag} ${name.padEnd(14)} ${page.url().replace(base, '').padEnd(34)} 첫화면 ${String(chars).padStart(4)}자 가로넘침 ${overflow}`);
  }
  await page.goto(`${base}/?lng=ko`, { waitUntil: 'networkidle' });
  await shot('1-start');
  await page.click('[data-main]');
  await page.waitForURL(/choose/);
  await shot('1b-choose');
  await page.click('[data-choice="person"]');
  await shot('2-person');
  await page.click('[data-choice="attack"]');
  await shot('3-predict');
  await page.goto(`${base}/person/next?from=attack&lng=ko`, { waitUntil: 'networkidle' });
  await shot('4-next-person');
  await page.goto(`${base}/deeper?track=H&lng=ko`, { waitUntil: 'networkidle' });
  await shot('5-deeper-H');
  await page.goto(`${base}/agent?lng=ko`, { waitUntil: 'networkidle' });
  await shot('6-agent-pick');
  await page.goto(`${base}/agent/next?lng=ko`, { waitUntil: 'networkidle' });
  await shot('7-next-agent');
  await page.goto(`${base}/attack?lng=ko`, { waitUntil: 'networkidle' });
  log.push(`${tag} old cover /attack -> ${page.url().replace(base, '')}`);
  console.log(log.join('\n'));
  if (errors.length) console.log(tag, 'errors', errors.slice(0, 3));
  await context.close();
}
await browser.close();
