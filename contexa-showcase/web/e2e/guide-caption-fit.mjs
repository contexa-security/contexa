// Measures every caption line of every guide video on the real page (가이드영상-계획.md): Korean and English, at 1440
// and 390 px, each line one row (its box no taller than the shortest line's), not cut off at either side, and at the
// bottom of the video. The check paints the caption box a marking colour and hides the player's controls, which would
// lift the caption while paused; it changes nothing else. Writes a capture of the longest line of each run.
// Usage (web folder): node e2e/guide-caption-fit.mjs [base url] [out dir]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const base = process.argv[2] ?? 'http://127.0.0.1:19180';
const out = process.argv[3] ?? 'test-results/guide-caption-fit';
mkdirSync(out, { recursive: true });
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
  });
  const page = await context.newPage();
  // The screens with a guide: 2-1 (the console) and 6-1 (the business agent, docs/agent A7-4).
  for (const screen of ['/attack/request', '/agent/request']) {
    await page.goto(`${base}${screen}${language === 'en' ? '?lng=en' : ''}`, {
      waitUntil: 'networkidle',
    });
    for (const button of await page.locator('[data-zone="title"] button[aria-haspopup="dialog"]').all()) {
      await button.click();
      const video = page.locator('dialog[open] video');
      await video.evaluate(
        (element) =>
          new Promise((resolve) => {
            element.controls = false;
            const track = [...element.textTracks].find((candidate) => candidate.mode === 'showing');
            if (track?.cues?.length) resolve();
            else
              element
                .querySelector('track[default]')
                ?.addEventListener('load', () => resolve(), { once: true });
          }),
      );
      const marking = await page.addStyleTag({
        content: 'video::cue { background: rgb(255 0 255) !important; color: rgb(255 0 255) !important; }',
      });
      const cues = await video.evaluate((element) =>
        [...[...element.textTracks].find((track) => track.mode === 'showing').cues].map((cue) => ({
          text: cue.text,
          at: (cue.startTime + cue.endTime) / 2,
        })),
      );
      const boxes = [];
      for (const cue of cues) {
        await video.evaluate((element, at) => {
          element.currentTime = at;
          return new Promise((resolve) =>
            element.addEventListener('seeked', () => resolve(), { once: true }),
          );
        }, cue.at);
        await page.waitForTimeout(150);
        const shot = await video.screenshot();
        const box = await page.evaluate(async (data) => {
          const image = new Image();
          image.src = `data:image/png;base64,${data}`;
          await image.decode();
          const canvas = document.createElement('canvas');
          canvas.width = image.width;
          canvas.height = image.height;
          const context2d = canvas.getContext('2d');
          context2d.drawImage(image, 0, 0);
          const { data: pixels } = context2d.getImageData(0, 0, image.width, image.height);
          let top = null;
          let bottom = null;
          let left = image.width;
          let right = -1;
          for (let y = 0; y < image.height; y += 1) {
            for (let x = 0; x < image.width; x += 1) {
              const i = (y * image.width + x) * 4;
              if (pixels[i] > 200 && pixels[i + 1] < 70 && pixels[i + 2] > 200) {
                top ??= y;
                bottom = y;
                left = Math.min(left, x);
                right = Math.max(right, x);
              }
            }
          }
          return { width: image.width, height: image.height, top, bottom, left, right };
        }, shot.toString('base64'));
        boxes.push({ text: cue.text, ...box });
      }
      const shown = boxes.filter((box) => box.top !== null);
      const row = Math.min(...shown.map((box) => box.bottom - box.top + 1));
      for (const box of boxes) {
        const problems = [];
        if (box.top === null) problems.push('not shown');
        else {
          if (box.bottom - box.top + 1 > row * 1.3)
            problems.push(`taller than one row (${box.bottom - box.top + 1} px)`);
          if (box.left <= 1 || box.right >= box.width - 2) problems.push('cut off at a side');
          if (box.height - box.bottom > box.height * 0.08)
            problems.push(`not at the bottom (${box.height - box.bottom} px up)`);
        }
        failed += problems.length > 0 ? 1 : 0;
        report.push({ language, width, text: box.text, problems });
      }
      // A capture of the longest line as the visitor sees it (without the marking colour).
      const longest = boxes.reduce((a, b) => (b.right - b.left > a.right - a.left ? b : a));
      await marking.evaluate((element) => element.remove());
      await video.evaluate(
        (element, at) => {
          element.currentTime = at;
          return new Promise((resolve) =>
            element.addEventListener('seeked', () => resolve(), { once: true }),
          );
        },
        cues.find((cue) => cue.text === longest.text).at,
      );
      await page.waitForTimeout(300);
      await video.screenshot({ path: join(out, `caption-${screen.split('/')[1]}-${language}-${width}.png`) });
      report.push({ screen, language, width, rowPx: row, longest: longest.text, cues: cues.length });
      await page.keyboard.press('Escape');
    }
  }
  await context.close();
}
await browser.close();
writeFileSync(join(out, 'fit.json'), JSON.stringify(report, null, 2));
console.log(
  JSON.stringify(
    report.filter((entry) => entry.problems?.length || entry.rowPx),
    null,
    2,
  ),
);
console.log(
  failed === 0 ? 'every caption line fits one row at the bottom' : `${failed} caption lines do not fit`,
);
process.exitCode = failed === 0 ? 0 : 1;
