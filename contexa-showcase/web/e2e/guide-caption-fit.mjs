// Measures every caption line of every guide video in the real window (가이드영상-제작기획안.md 6.2절, G-8): Korean and
// English, at 1440 and 390 px. Each line must show on the band under the video in one row (not wider than the band), at
// least 24 px (wide) or 18 px (phone), bold, white on the solid band, outside the video's box (it covers none of the
// recorded screen), and stay long enough to be read (guideCaptions.mjs cueSeconds). Writes a capture of the longest line
// of each run. The wide window uses the files `<id>.<lang>.vtt`, the phone the ones cut finer, `<id>.<lang>.m.vtt`.
// Usage (web folder): node e2e/guide-caption-fit.mjs [base url] [out dir] [--fake]
// --fake lists every guide of the plan as recorded with the old recording's files, to try the measurement before the
// new videos exist.
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { cueSeconds } from './guideCaptions.mjs';

const args = process.argv.slice(2).filter((arg) => !arg.startsWith('--'));
const fake = process.argv.includes('--fake');
const base = args[0] ?? 'http://127.0.0.1:19180';
const out = args[1] ?? 'test-results/guide-caption-fit';
mkdirSync(out, { recursive: true });

const list = JSON.parse(readFileSync('src/components/guide/guides.json', 'utf-8'));
const journey = JSON.parse(readFileSync('src/journey/route.json', 'utf-8'));
const pathOf = (screen) =>
  screen === 'benchmark' || screen === 'lab' ? `/${screen}` : journey.find((found) => found.number === screen)?.path;
const recorded = JSON.parse(readFileSync('public/guides/guides.json', 'utf-8')).console;
const fakeManifest = JSON.stringify(
  Object.fromEntries(
    Object.entries(list)
      .filter(([, entry]) => entry.kind !== 'legacy')
      .map(([id]) => [id, recorded]),
  ),
);

const only = process.env.ONLY?.split(',') ?? null;
const MIN_FONT = { 1440: 24, 390: 18 };
const report = [];
let failed = 0;

const browser = await chromium.launch();
for (const [language, width] of [
  ['ko', 1440],
  ['en', 1440],
  ['ko', 390],
  ['en', 390],
]) {
  const context = await browser.newContext({
    viewport: { width, height: width === 390 ? 844 : 900 },
    locale: language,
    reducedMotion: 'reduce',
  });
  const page = await context.newPage();
  if (fake) {
    await page.route('**/guides/guides.json', (route) =>
      route.fulfill({ contentType: 'application/json', body: fakeManifest }),
    );
  }
  const manifest = fake
    ? JSON.parse(fakeManifest)
    : await (await context.request.get(`${base}/guides/guides.json`)).json();
  for (const [id, entry] of Object.entries(list)) {
    const screen = entry.screens.map(pathOf).find(Boolean);
    if (entry.kind === 'legacy' || !manifest[id] || !screen || (only && !only.includes(id))) continue;
    await page.goto(`${base}${screen}?lng=${language}`, { waitUntil: 'networkidle' });
    await page.locator('[data-guide-link]').first().click();
    const video = page.locator('dialog[open] video');
    const cues = await video.evaluate(
      (element, lang) =>
        new Promise((resolve) => {
          element.controls = false;
          const track = [...element.textTracks].find((candidate) => candidate.language === lang);
          const read = () => {
            track.mode = 'showing';
            resolve([...track.cues].map((cue) => ({ text: cue.text, from: cue.startTime, to: cue.endTime })));
          };
          if (track.cues?.length) read();
          else element.querySelector(`track[srclang="${lang}"]`).addEventListener('load', read, { once: true });
          track.mode = 'showing';
        }),
      language,
    );
    let longest = { text: '', width: -1 };
    for (const cue of cues) {
      const at = (cue.from + cue.to) / 2;
      await video.evaluate((element, time) => {
        element.currentTime = time;
        return new Promise((resolve) => element.addEventListener('seeked', () => resolve(), { once: true }));
      }, at);
      await page.waitForFunction(
        (text) => document.querySelector('[data-caption-band]')?.textContent === text,
        cue.text,
        { timeout: 2000 },
      ).catch(() => undefined);
      const band = await page.locator('dialog[open] [data-caption-band]').evaluate((element) => {
        const style = getComputedStyle(element);
        const video = element.closest('[data-player]').querySelector('video').getBoundingClientRect();
        const box = element.getBoundingClientRect();
        return {
          text: element.textContent,
          fontPx: parseFloat(style.fontSize),
          weight: Number(style.fontWeight),
          color: style.color,
          background: style.backgroundColor,
          oneRow: element.scrollWidth <= element.clientWidth + 1,
          below: box.top >= video.bottom - 1,
          textWidth: element.scrollWidth,
        };
      });
      const problems = [];
      if (band.text !== cue.text) problems.push(`band shows "${band.text}"`);
      if (!band.oneRow) problems.push('wider than the band');
      if (band.fontPx < MIN_FONT[width]) problems.push(`font ${band.fontPx}px under ${MIN_FONT[width]}px`);
      if (band.weight < 700) problems.push(`weight ${band.weight}`);
      if (band.color !== 'rgb(255, 255, 255)') problems.push(`color ${band.color}`);
      if (!band.below) problems.push('over the recorded screen');
      const needed = cueSeconds(cue.text, language);
      const stayed = cue.to - cue.from;
      if (stayed < needed - 0.001) problems.push(`stays ${stayed.toFixed(2)} s, needs ${needed.toFixed(2)} s`);
      failed += problems.length > 0 ? 1 : 0;
      report.push({ id, language, width, text: cue.text, fontPx: band.fontPx, problems });
      if (band.textWidth > longest.width) longest = { text: cue.text, width: band.textWidth, at };
    }
    await video.evaluate((element, time) => {
      element.currentTime = time;
      return new Promise((resolve) => element.addEventListener('seeked', () => resolve(), { once: true }));
    }, longest.at);
    await page.waitForTimeout(200);
    await page.locator('dialog[open] [data-player]').screenshot({ path: join(out, `caption-${id}-${language}-${width}.png`) });
    report.push({ id, language, width, cues: cues.length, longest: longest.text });
    await page.keyboard.press('Escape');
  }
  await context.close();
}
await browser.close();
writeFileSync(join(out, 'fit.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report.filter((entry) => entry.problems?.length || entry.cues !== undefined), null, 2));
console.log(failed === 0 ? 'every caption line fits the band' : `${failed} caption lines do not fit the band`);
process.exitCode = failed === 0 ? 0 : 1;
