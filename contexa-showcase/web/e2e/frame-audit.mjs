// The redesign's automatic check (docs/showcase/화면재편-구현계획.md R0-3, RC-1 to RC-3, section 11): opens every
// screen of a list at 1440 and 390 px on a running portal, measures it with the same definitions as the 2026-10-18
// baseline (redesign-audit/audit.json), and judges it:
//   RC-1 limits: pressables 3, boxes 4, numbers 8, font sizes 4 (3 on phones), page length at 390 px 1,266, gaps at
//        390 px p10 >= 12 and median >= 24. A screen marked data-type="table" skips the number limit (plan 5).
//   RC-2 words: no old term, stage-unit name, engine code or run id in the visible Korean text (originals aside).
//   RC-3 copy: the headline, the guide line and the main button equal the screen's dictionary keys
//        (screen.{no}.title / guide / next), where the screen has them.
// Inside a redesigned frame only the zones title, body and source are measured ([data-zone]); on an old screen the
// whole main, as the baseline did. Exits 1 when any screen fails. Read only for the portal; each context is a new
// visitor, as any visitor.
// Usage: node e2e/frame-audit.mjs <outDir> [--screens <json>] [--base <url>] [--widths 1440,390] [--measure-only]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';
import { judge, measure } from './frameMeasure.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
const outDir = args[0];
const base = option('--base', 'http://127.0.0.1:19180');
const widths = option('--widths', '1440,390').split(',').map(Number);
const measureOnly = args.includes('--measure-only');
// The screens of "learn more" by default (최종화면-구현계획 F3-6); the main flow has its own check (main-audit.mjs).
const routeFile = path.join(here, '..', 'src', 'journey', 'topics.json');
const screensFile = option('--screens', fs.existsSync(routeFile) ? routeFile : null);
if (!outDir || !screensFile) {
  console.error('usage: node e2e/frame-audit.mjs <outDir> [--screens <json>] [--base <url>] [--widths 1440,390]');
  process.exit(2);
}
const ko = JSON.parse(fs.readFileSync(path.join(here, '..', 'src', 'i18n', 'ko.json'), 'utf8'));
const listed = JSON.parse(fs.readFileSync(screensFile, 'utf8'));
// A topics file lists topics: each screen expects the next screen of its topic by name, the last one the hub.
const screens = listed.some((entry) => Array.isArray(entry.screens))
  ? listed.flatMap((topic) =>
      topic.screens.map((screen, index) => {
        const next = topic.screens[index + 1];
        return {
          ...screen,
          expectMain: next ? ko['frame.nextNamed'].replace('{{name}}', ko[`more.name.${next.id}`]) : ko['more.toHub'],
        };
      }),
    )
  : listed;

fs.mkdirSync(outDir, { recursive: true });
const browser = await chromium.launch();
const results = [];
for (const width of widths) {
  const context = await browser.newContext({ viewport: { width, height: width === 390 ? 844 : 1000 }, locale: 'ko' });
  await context.addInitScript(() => {
    try {
      localStorage.setItem('showcase.language', 'ko');
    } catch {
      // Storage may be closed; the browser language is Korean anyway.
    }
  });
  const page = await context.newPage();
  for (const screen of screens) {
    const id = screen.number ? `${screen.number}-${screen.id}` : screen.id;
    try {
      // Screens that poll a run never go network-idle; wait for the load, a headline, then a short settle.
      await page.goto(base + screen.path, { waitUntil: 'load', timeout: 45000 });
      await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
      await page.locator('h1, dialog[open] h2').first().waitFor({ timeout: 15000 }).catch(() => {});
      await page.waitForTimeout(1500);
      const m = await page.evaluate(measure);
      await page.screenshot({ path: path.join(outDir, `${id}-${width}.png`), fullPage: true });
      const fails = judge(screen, width, m, ko, measureOnly);
      const { pageText, ...kept } = m;
      results.push({ id, path: screen.path, width, ...kept, fails });
      console.log(width, id, fails.length ? `FAIL ${fails.length}: ${fails.slice(0, 4).join('; ')}` : 'PASS');
    } catch (error) {
      results.push({ id, path: screen.path, width, error: String(error).slice(0, 200), fails: ['error'] });
      console.log(width, id, 'ERROR', String(error).slice(0, 120));
    }
  }
  await context.close();
}
await browser.close();
fs.writeFileSync(path.join(outDir, 'frame-audit.json'), JSON.stringify(results, null, 1));
const failed = results.filter((r) => r.fails.length);
console.log(`done ${results.length} checks, ${failed.length} failing`);
process.exit(failed.length ? 1 : 0);
