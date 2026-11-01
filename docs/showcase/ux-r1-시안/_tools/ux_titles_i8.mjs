// UX-R1 I-8 title check (기획안 11절, DEC-73): opens every built screen in both languages, collects its headings
// (h1 ~ h3, the ones for assistive technology too), its tab names and its step names, and finds where each new title of
// 기획안 11절 is shown — the whole title, or each part of a title that joins several with " · ". A number in a title is
// matched as any number (the screens show the measured counts). Live screens are not opened: one may act on a waiting run.
//
//   node ux_titles_i8.mjs --base http://localhost:5180 --out <file.json>
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';

const require = createRequire('E:/projects/contexa/contexa-showcase/web/package.json');
const { chromium } = require('playwright');

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index > 0 ? process.argv[index + 1] : fallback;
}
const base = arg('base', 'http://localhost:5180');
const out = arg('out', 'titles.json').replace(/^\/([a-z])\//i, (_, drive) => `${drive.toUpperCase()}:/`);

const PATHS = [
  '/', '/simulate/person', '/simulate/person/S13/review', '/simulate/person/S13/result', '/simulate/person/S13T/review',
  '/simulate/person/S13T/result', '/simulate/person/S13T/result?tab=compare', '/simulate/person/S16/review',
  '/simulate/person/S16/result', '/simulate/agent', '/simulate/agent/T5/review', '/simulate/agent/T5/result',
  '/simulate/surge', '/simulate/surge?tab=repeat', '/simulate/policy?tab=threshold', '/simulate/policy?tab=compose',
  '/simulate/policy?tab=agent', '/runs', '/runs/run-f2b58445fb72?tab=summary', '/runs/run-f2b58445fb72?tab=evidence',
  '/runs/run-f2b58445fb72?tab=prompt', '/runs/run-f2b58445fb72?tab=response', '/engine?tab=flow', '/engine?tab=baseline',
  '/engine?tab=facts', '/engine?tab=prompt', '/engine?tab=seal', '/compare?tab=rule', '/compare?tab=change',
  '/compare?tab=runs', '/validation?tab=summary', '/validation?tab=controls', '/validation?tab=scenarios',
  '/validation?tab=scenarios&case=S13', '/validation?tab=quality', '/validation?tab=agent', '/validation?tab=limits',
  '/validation?tab=method', '/adopt', '/metrics', '/tour', '/privacy', '/glossary',
];

// 기획안 11절: number, Korean title, English title.
const doc = readFileSync('E:/projects/contexa/docs/showcase/데모-화면-전면개선-기획안.md', 'utf8').split('\n');
const from = doc.findIndex((line) => line.startsWith('## 11.'));
const rows = [];
for (const line of doc.slice(from + 1)) {
  if (line.startsWith('## ')) break;
  const cells = line.split('|').slice(1, -1).map((cell) => cell.trim());
  if (cells.length === 5 && cells[0] !== '번호' && !cells[0].startsWith('---')) {
    rows.push({ number: cells[0], where: cells[2], ko: cells[3], en: cells[4] });
  }
}

const browser = await chromium.launch();
const seen = {};
for (const lang of ['ko', 'en']) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await context.addInitScript((l) => {
    try {
      localStorage.setItem('showcase.language', l);
    } catch {}
  }, lang);
  const page = await context.newPage();
  for (const path of PATHS) {
    await page.goto(`${base}${path}`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    const texts = await page.evaluate(() => [
      ...[...document.querySelectorAll('main h1, main h2, main h3, main [role="tab"], main [aria-label] li, main ol li b')]
        .map((el) => el.textContent.replace(/\s+/g, ' ').trim()),
      // A title given as a name for assistive technology (a list, a region, a group).
      ...[...document.querySelectorAll('main [aria-label]')].map((el) => el.getAttribute('aria-label').trim()),
    ].filter(Boolean));
    (seen[path] ??= {})[lang] = [...new Set(texts)];
  }
  await context.close();
}
await browser.close();

/** A title as a pattern: any number for a number, the rest as written. */
const pattern = (title) =>
  new RegExp(title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\d+/g, '\\d+').replace(/ n /g, ' \\d+ '));
function where(title, lang) {
  const re = pattern(title);
  return Object.entries(seen)
    .filter(([, texts]) => texts[lang].some((text) => re.test(text)))
    .map(([path]) => path);
}
const report = rows.map((row) => {
  const parts = row.ko.split(/ · |\(/).map((part) => part.replace(/\)$/, '').trim()).filter(Boolean);
  return {
    ...row,
    koWhole: where(row.ko, 'ko'),
    koParts: Object.fromEntries(parts.map((part) => [part, where(part, 'ko')])),
    enWhole: where(row.en.replace(/\.$/, ''), 'en'),
  };
});
writeFileSync(out, JSON.stringify({ base, checkedAt: new Date().toISOString(), rows: report, seen }, null, 1));
const missing = report.filter((row) => row.koWhole.length === 0 && Object.values(row.koParts).every((paths) => paths.length === 0));
console.log(`rows ${report.length}, Korean title found whole ${report.filter((row) => row.koWhole.length).length}, not found at all ${missing.length}`);
for (const row of missing) console.log('NOT FOUND', row.number, row.ko);
