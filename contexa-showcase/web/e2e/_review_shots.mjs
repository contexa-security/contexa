// 일회용: 방문자 화면의 첫 화면을 데스크톱·모바일로 찍어 검토합니다(코드 변경 없음). 삭제 대상 보조 파일.
import { chromium } from '@playwright/test';
import fs from 'node:fs';

const base = 'http://127.0.0.1:19180';
const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const pages = [
  ['/', 'home'], ['/intro/approaches', 'approaches'], ['/attack', 'attack'], ['/attack/request', 'attack-request'],
  ['/evidence/verdict', 'evidence-verdict'], ['/normal', 'normal'], ['/insider', 'insider'], ['/agent', 'agent'],
  ['/agent/request', 'agent-request'], ['/compare', 'compare'], ['/compare/rule', 'compare-rule'],
  ['/summary', 'summary'], ['/more', 'more'], ['/benchmark', 'bench'], ['/benchmark/agent', 'bench-agent'],
  ['/benchmark/limits', 'bench-limits'], ['/lab', 'lab'], ['/adopt', 'adopt'],
];
const sizes = [['d', 1440, 900], ['m', 390, 844]];
const browser = await chromium.launch();
const report = [];
for (const [width, w, h] of sizes.map(([n, w, h]) => [n, w, h])) {
  const context = await browser.newContext({ viewport: { width: w, height: h }, locale: 'ko-KR', reducedMotion: 'reduce' });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 200)));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text().slice(0, 160)); });
  for (const [path, name] of pages) {
    errors.length = 0;
    try {
      await page.goto(`${base}${path}?lng=ko`, { waitUntil: 'networkidle', timeout: 30000 });
      await page.waitForTimeout(700);
      await page.screenshot({ path: `${out}/${width}-${name}.png`, fullPage: false });
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      const height = await page.evaluate(() => document.documentElement.scrollHeight);
      report.push(`${width} ${name} overflow=${overflow} pageHeight=${height} errors=${errors.length ? errors.slice(0, 2).join(' | ') : 0}`);
    } catch (e) {
      report.push(`${width} ${name} FAILED ${String(e).slice(0, 120)}`);
    }
  }
  await context.close();
}
await browser.close();
console.log(report.join('\n'));
