// 일회용: 영상 목록 화면(/videos)과 메뉴 항목을 두 폭에서 확인합니다. 목록은 가로채서 넣습니다. 삭제 대상 보조 파일.
// 사용: node e2e/_review_videos.mjs <출력 폴더> [언어]
import AxeBuilder from '@axe-core/playwright';
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const out = process.argv[2];
const lng = process.argv[3] ?? 'ko';
const base = process.env.BASE ?? 'http://127.0.0.1:5180';
fs.mkdirSync(out, { recursive: true });

const one = JSON.parse(fs.readFileSync(new URL('../public/guides/guides.json', import.meta.url), 'utf8')).console;
const ids = ['start', 'request', 'result', 'delegate', 'agentResult', 'evidence', 'rules', 'benchmark', 'lab'];
const fake = Object.fromEntries(ids.map((id, index) => [id, { ...one, durationSec: 60 + index * 9 }]));

const browser = await chromium.launch();
for (const [name, width, height] of [['d', 1440, 900], ['m', 390, 844]]) {
  const context = await browser.newContext({ viewport: { width, height }, locale: lng === 'ko' ? 'ko-KR' : 'en-US', reducedMotion: 'reduce' });
  const page = await context.newPage();
  await page.route('**/guides/guides.json', (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify(fake) }));
  await page.goto(`${base}/videos?lng=${lng}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(600);
  const info = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    inner: window.innerWidth,
    pageHeight: document.documentElement.scrollHeight,
    rows: document.querySelectorAll('main ul > li > div > b').length,
    groups: [...document.querySelectorAll('main h2')].map((h) => h.textContent),
  }));
  const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
  const serious = axe.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id);
  console.log(name, JSON.stringify(info), 'axe', JSON.stringify(serious));
  await page.screenshot({ path: `${out}/${name}-videos.png`, fullPage: name === 'd' });
  // the menu entry
  await page.goto(`${base}/choose?lng=${lng}`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /메뉴|Menu/ }).first().click();
  const entry = await page.getByRole('dialog').getByRole('link', { name: /미리보기 영상|Preview videos/ }).count();
  console.log(name, 'menu entry', entry);
  await context.close();
}
await browser.close();
