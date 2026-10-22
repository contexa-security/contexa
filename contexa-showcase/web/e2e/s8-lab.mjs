// S8 check on the real stack (C-3, C-4, C-5, C-16; 화면재편 R7 RO-2): the lab in the redesigned frame, in Korean and
// English. The entrance, picking a situation, changing one condition, the comparison before sending, predicting and
// sending (one real run per language), the result, and the rule tightening with one setting changed. Every screen is
// captured at 390, 768, 1024 and 1440 px and checked like the routes.
// Usage: node e2e/s8-lab.mjs <out dir> [base url]
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { capture, inspect } from './screenCheck.mjs';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://127.0.0.1:5180';
const DICTIONARIES = {
  ko: JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8')),
  en: JSON.parse(readFileSync('src/i18n/en.json', 'utf-8')),
};
mkdirSync(out, { recursive: true });

const browser = await chromium.launch();
const report = [];
const values = [];
for (const language of ['ko', 'en']) {
  const m = DICTIONARIES[language];
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    locale: language,
    reducedMotion: 'reduce',
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 300)));
  const open = async (name, path) => {
    await page.goto(`${base}${path}${path.includes('?') ? '&' : '?'}lng=${language}`, {
      waitUntil: 'networkidle',
    });
    await page.waitForTimeout(700);
    values.push({ language, screen: name, heading: await page.locator('h1').innerText() });
    await capture(page, out, language, name, report);
  };

  await open('lab-0', '/lab');
  await open('lab-1', '/lab/case?case=A3T');
  await open('lab-2', '/lab/change?case=A3T&field=approval&approval=false');
  await open('lab-compare', '/lab/before?case=A3T&approval=false');
  await open('lab-send', '/lab/send?case=A3T&approval=false');

  // One real run: the call, then the run screen once it ended and the result.
  const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // The radio itself is visually hidden; a visitor presses its label, as here.
  await page.locator('label').filter({ has: page.getByRole('radio', { name: new RegExp(escape(m['lab.r7.send.call.ATTACK'])) }) }).click();
  await page.getByRole('button', { name: m['lab.r7.send.send'] }).click();
  await page.waitForURL(/sent=/, { timeout: 60_000 });
  await page.getByRole('link', { name: m['lab.r7.run.next'] }).waitFor({ timeout: 240_000 });
  await capture(page, out, language, 'lab-run', report);
  await page.getByRole('link', { name: m['lab.r7.run.next'] }).click();
  await page.waitForURL(/\/lab\/result/);
  await page.waitForTimeout(1200);
  values.push({ language, screen: 'lab-3', heading: await page.locator('h1').innerText(), url: page.url() });
  await capture(page, out, language, 'lab-3', report);

  await open('lab-rules', '/lab/rules');
  await open('lab-rules-c2', '/lab/rules?rule=approval&value=off');
  values.push({ language, screen: 'errors', errors });
  await context.close();
}
await browser.close();
writeFileSync(join(out, 's8-report.json'), JSON.stringify({ report, values }, null, 1));
for (const row of report.filter((entry) => entry.width === 1440)) {
  console.log(
    `${row.language} ${row.name}: main buttons ${row.limits?.primaries}, numbers ${row.limits?.numbers}, english ${JSON.stringify(row.language === 'ko' ? row.limits?.english : [])}`,
  );
}
for (const row of report) {
  if (row.overflow || row.bandOverlap || row.singleLetter.length || row.serious.length) {
    console.log(
      `${row.language} ${row.name} ${row.width}: overflow ${row.overflow}, band overlap ${row.bandOverlap}, single-letter ${JSON.stringify(row.singleLetter)}, axe ${JSON.stringify(row.serious)}`,
    );
  }
}
console.log(`screens checked ${report.length}`);
console.log(JSON.stringify(values, null, 1).slice(0, 4000));
