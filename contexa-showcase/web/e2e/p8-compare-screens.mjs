// N-DEP-1 and N-DEP-2 screen check (C-3, C-4, C-5 of the screen design): the comparison screens a v20
// decision feeds (try 1's and try 2's comparison, the decision details' received tab, the lab's
// comparison before sending), at the four widths in ko and en, through the capture every screen stage
// used (screenCheck.mjs). Unlike p7-screens.mjs it names the English words outside the originals of a
// Korean screen as a problem (C-5). Every run named here is a recorded run; nothing is sent.
// Usage: node e2e/p8-compare-screens.mjs <out dir> <base url> <run with a v20 decision>
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { capture } from './screenCheck.mjs';

const [out, base, run] = process.argv.slice(2);
mkdirSync(out, { recursive: true });

const SCREENS = [
  { name: 'E1-compare', path: '/try/attacker/compare' },
  { name: 'E2-compare', path: '/try/owner/compare' },
  { name: 'detail-received', path: `/run/${run}/detail?step=1&tab=received`, window: true },
  { name: 'lab-before', path: '/lab/before?case=A3T&approval=false' },
];

const browser = await chromium.launch();
const report = [];
for (const language of ['ko', 'en']) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    locale: language,
    reducedMotion: 'reduce',
  });
  const page = await context.newPage();
  for (const screen of SCREENS) {
    await page.goto(`${base}${screen.path}${screen.path.includes('?') ? '&' : '?'}lng=${language}`, {
      waitUntil: 'networkidle',
    });
    // N-TST-2: a window is an open <dialog> element (src/components/common/Modal.tsx) without a role attribute, so
    // '[role="dialog"]' never matched it and the main area behind the window was read. A screen that opens a window
    // (window: true) waits for the window's title, and any open window is the part that is read.
    await page.locator(screen.window ? 'dialog[open] h2[data-modal-title]' : 'main h1').first().waitFor();
    await page.waitForTimeout(800);
    const windowOpen = screen.window === true || (await page.locator('dialog[open]').count()) > 0;
    const root = windowOpen ? 'dialog[open]' : 'main';
    const from = report.length;
    await capture(page, out, language, screen.name, report, root);
    for (const row of report.slice(from)) {
      row.root = root;
    }
  }
  await context.close();
}
await browser.close();
writeFileSync(join(out, 'p8-compare-screens.json'), JSON.stringify({ screens: SCREENS, report }, null, 2));
for (const row of report) {
  const problems = [];
  if (row.overflow > 0) problems.push(`overflow ${row.overflow}`);
  if (row.singleLetter?.length) problems.push(`single letter ${row.singleLetter.length}`);
  if (row.bandOverlap > 0) problems.push(`band overlap ${row.bandOverlap}`);
  if (row.serious?.length) problems.push(`axe ${row.serious.map((v) => v.id ?? v).join(',')}`);
  if (row.language === 'ko' && row.limits?.english?.length) {
    problems.push(`english ${row.limits.english.join(',')}`);
  }
  if (row.phone) {
    for (const [key, value] of Object.entries(row.phone)) {
      if (Array.isArray(value) ? value.length > 0 : value === false) problems.push(`phone ${key}`);
    }
  }
  console.log(`${row.language} ${row.width} ${row.name} ${problems.length ? problems.join(' | ') : 'ok'}`);
}
