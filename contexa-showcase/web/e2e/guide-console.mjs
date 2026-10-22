// Guide video 1 (가이드영상-계획.md 3절): how to read the live decision console. Records the real stack at 1440 x 900 in
// Korean: the 2-1 request, one live send of the attack case and the 2-2 console while Contexa decides. Drawn over the
// site are only a highlight frame, the pointer, the three judgment chips' meanings in the last scene and, once Contexa
// answered, a blur over its result with "send it yourself" (plan principle 2). The captions are the dictionaries'
// guide.console.* lines in the order of src/components/guide/guides.json, written as WebVTT at the times they were
// shown. Writes public/guides/console.webm, console.ko.vtt, console.en.vtt and the console entry of
// public/guides/guides.json. One live send (the attack case, the light model).
// Usage (web folder): node e2e/guide-console.mjs [base url]
import { chromium } from '@playwright/test';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LINE_LIMIT, vtt } from './guideCaptions.mjs';

const base = process.argv[2] ?? 'http://127.0.0.1:19180';
const ko = JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8'));
const en = JSON.parse(readFileSync('src/i18n/en.json', 'utf-8'));
const script = JSON.parse(readFileSync('src/components/guide/guides.json', 'utf-8')).console;
const OUT = 'public/guides';
const ID = 'console';
// The screens are the final screen design v4 (docs/showcase/Contexa_최종화면설계서_v4.pptx).
const SCREENS = 'v4';
const RUN_TIMEOUT = 180_000;
const SIZE = { width: 1440, height: 900 };

/** The words drawn over the site, all from the Korean dictionary the recorded screens use. */
const overlayWords = {
  hidden: ko['guide.hidden'],
  chips: ['ALLOW', 'CHALLENGE', 'BLOCK'].map((action) => ({
    kind: action,
    name: ko[`main.verdict.${action}`],
    meaning: ko[`compare.result.${action}`],
  })),
};

/**
 * The layer over the site. It never changes the page's own elements: it adds a style that hides Contexa's result once
 * its lane stops holding (pure CSS, so no frame shows the result before it is hidden; values are hidden outright, as a
 * blur still showed their colours) and a few fixed boxes.
 */
function overlay(words) {
  const style = document.createElement('style');
  const done = 'li[data-control="D"]:not(:has([data-holding]))';
  style.textContent = `
    html[data-guide-recording] ${done} > [class*="_track_"],
    html[data-guide-recording] ${done} > [class*="_laneEnd_"],
    html[data-guide-recording] [class*="_leak_"] > [class*="_counter_"]:nth-child(2) [class*="_counterValue_"]:not([data-tone="idle"]),
    html[data-guide-recording] [class*="_stamp_"],
    html[data-guide-recording] [class*="_riskValue_"]:not([data-waiting]),
    html[data-guide-recording] [class*="_riskFill_"] { visibility: hidden !important; }
    html[data-guide-recording] [class*="_factsSource_"],
    html[data-guide-recording] [class*="_logLine_"][data-tone="allow"] > span:last-child,
    html[data-guide-recording] [class*="_logLine_"][data-tone="stop"] > span:last-child,
    html[data-guide-recording] [class*="_recovery_"] { filter: blur(10px) grayscale(1) !important; opacity: 0.6; }
    html[data-guide-recording] [data-zone="title"] [aria-haspopup="dialog"] { visibility: hidden !important; }
    .guide-hidden, #guide-box, #guide-pointer, #guide-chips, #guide-end { position: fixed; z-index: 2147483647; pointer-events: none; }
    #guide-box { border: 3px solid #f2c14e; border-radius: 12px; box-shadow: 0 0 0 9999px rgb(4 8 16 / 38%);
      transition: all 260ms ease; opacity: 0; }
    #guide-pointer { inline-size: 22px; block-size: 22px; margin: -11px 0 0 -11px; border-radius: 50%;
      background: rgb(242 193 78 / 55%); border: 2px solid #fff; transition: transform 120ms; }
    #guide-pointer[data-down] { transform: scale(0.7); }
    .guide-hidden { display: none; padding: 8px 16px; border-radius: 999px; background: #f2c14e; color: #171206;
      font: 600 17px/1.3 var(--font-sans); transform: translate(-50%, -50%); white-space: nowrap; }
    .guide-hidden[data-on] { display: block; }
    #guide-chips { display: none; gap: 28px; padding: 18px 20px; border-radius: 14px; background: #0f1a2e;
      border: 1px solid #f2c14e; color: #e8edf5; font: 17px/1.4 var(--font-sans); }
    #guide-chips[data-on] { display: flex; }
    #guide-chips div { display: flex; gap: 14px; align-items: center; }
    #guide-chips b { min-inline-size: 92px; padding: 4px 12px; border-radius: 999px; text-align: center; color: #0b1220; }
    #guide-chips b[data-kind="ALLOW"] { background: #7fd19b; }
    #guide-chips b[data-kind="CHALLENGE"] { background: #f2c14e; }
    #guide-chips b[data-kind="BLOCK"] { background: #ff6b6b; }
    #guide-end { inset: 0; display: none; place-items: center; background: #0b1220; color: #e8edf5;
      font: 600 24px/1.5 var(--font-sans); text-align: center; }
    #guide-end[data-on] { display: grid; }
  `;
  const add = () => {
    if (document.getElementById('guide-box')) return;
    // The init script can run before the document has its root element; the layer is built once the body exists.
    document.documentElement.setAttribute('data-guide-recording', '');
    (document.head ?? document.documentElement).appendChild(style);
    const make = (id, text = '') => {
      const element = document.createElement('div');
      element.id = id;
      element.textContent = text;
      document.body.appendChild(element);
      return element;
    };
    const box = make('guide-box');
    const pointer = make('guide-pointer');
    const hiddenLane = make('guide-hidden-lane', words.hidden);
    const hiddenCount = make('guide-hidden-count', words.hidden);
    hiddenLane.className = 'guide-hidden';
    hiddenCount.className = 'guide-hidden';
    const chips = make('guide-chips');
    for (const chip of words.chips) {
      const row = document.createElement('div');
      const name = document.createElement('b');
      name.dataset.kind = chip.kind;
      name.textContent = chip.name;
      const meaning = document.createElement('span');
      meaning.textContent = chip.meaning;
      row.append(name, meaning);
      chips.appendChild(row);
    }
    make('guide-end');
    let targets = [];
    let answeredAt = null;
    window.__guide = {
      // Frames the union of the elements the selectors find, following them as the page moves.
      highlight(selectors) {
        targets = selectors;
      },
      clear() {
        targets = [];
      },
      chips(on) {
        chips.toggleAttribute('data-on', on);
      },
      // When Contexa's lane first stopped holding (the page's clock), or null while it still holds.
      answeredAt() {
        return answeredAt;
      },
      end(text) {
        const end = document.getElementById('guide-end');
        end.textContent = text;
        end.setAttribute('data-on', '');
      },
    };
    document.addEventListener('mousemove', (event) => {
      pointer.style.left = `${event.clientX}px`;
      pointer.style.top = `${event.clientY}px`;
    });
    document.addEventListener('mousedown', () => pointer.setAttribute('data-down', ''));
    document.addEventListener('mouseup', () => pointer.removeAttribute('data-down'));
    const frame = () => {
      const rects = targets
        .flatMap((selector) => [...document.querySelectorAll(selector)])
        .map((element) => element.getBoundingClientRect())
        .filter((rect) => rect.width > 0 && rect.height > 0);
      if (rects.length > 0) {
        const left = Math.min(...rects.map((rect) => rect.left)) - 8;
        const top = Math.min(...rects.map((rect) => rect.top)) - 8;
        const right = Math.max(...rects.map((rect) => rect.right)) + 8;
        const bottom = Math.max(...rects.map((rect) => rect.bottom)) + 8;
        Object.assign(box.style, {
          left: `${left}px`,
          top: `${top}px`,
          width: `${right - left}px`,
          height: `${bottom - top}px`,
          opacity: '1',
        });
      } else {
        box.style.opacity = '0';
      }
      // "Send it yourself" over each hidden value, once Contexa's lane stopped holding.
      const contexa = document.querySelector('li[data-control="D"]');
      const answered = contexa !== null && contexa.querySelector('[data-holding]') === null;
      if (answered && answeredAt === null) answeredAt = Date.now();
      const counter = document.querySelector(
        '[class*="_leak_"] > [class*="_counter_"]:nth-child(2) [class*="_counterValue_"]',
      );
      const place = (label, element, on) => {
        label.toggleAttribute('data-on', on && element !== null);
        if (on && element) {
          const rect = element.getBoundingClientRect();
          label.style.left = `${rect.left + rect.width / 2}px`;
          label.style.top = `${rect.top + rect.height / 2}px`;
        }
      };
      const lane = contexa?.querySelector(':scope > [class*="_track_"]') ?? null;
      place(hiddenLane, lane, answered);
      place(hiddenCount, counter, answered && counter?.getAttribute('data-tone') !== 'idle');
      // The three judgments sit in a row under the two counters, clear of the hidden values.
      const counters = document.querySelector('[class*="_leak_"]');
      if (counters) {
        const rect = counters.getBoundingClientRect();
        chips.style.left = `${rect.left}px`;
        chips.style.top = `${rect.bottom + 14}px`;
      }
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  };
  if (document.body) add();
  else document.addEventListener('DOMContentLoaded', add);
}

const browser = await chromium.launch();
const raw = mkdtempSync(join(tmpdir(), 'guide-console-'));
const context = await browser.newContext({
  viewport: SIZE,
  locale: 'ko',
  colorScheme: 'dark',
  recordVideo: { dir: raw, size: SIZE },
});
await context.addInitScript(overlay, overlayWords);
const page = await context.newPage();
const started = Date.now();
const problems = [];
page.on('pageerror', (error) => problems.push(String(error).slice(0, 300)));

const cues = [];
const at = () => (Date.now() - started) / 1000;
function cue(key) {
  if (!script.scenes.includes(key)) throw new Error(`not a scene of the guide: ${key}`);
  cues.push({ key, start: at() });
  console.log(`${at().toFixed(1)}s ${key}`);
}
const guide = (call, ...args) =>
  page.evaluate(([name, values]) => window.__guide[name](...values), [call, args]);
const highlight = (...selectors) => guide('highlight', selectors);
const wait = (ms) => page.waitForTimeout(ms);
const run = () =>
  page.evaluate(() =>
    fetch('/api/live/runs/current').then((response) => (response.ok ? response.json() : null)),
  );
/** Moves the pointer to the element's middle, or by `beside` pixels left of its left edge so no word is covered. */
async function point(locator, beside = null) {
  const box = await locator.boundingBox();
  if (box) {
    const x = beside === null ? box.x + box.width / 2 : box.x - beside;
    await page.mouse.move(x, box.y + box.height / 2, { steps: 18 });
  }
}

// 1. The request: what will go out, the prediction, Send. The page starts in the site's own background colour.
await page.setContent('<html style="background:#070c18"></html>');
await page.goto(`${base}/attack/request`, { waitUntil: 'networkidle' });
await page.getByText(ko['main.request.call.ALLOW'], { exact: true }).waitFor();
await wait(600);
cue('guide.console.request');
await highlight('section[aria-labelledby="request-info"]');
await point(page.locator('section[aria-labelledby="request-info"] dl'));
await wait(4_500);
await highlight('fieldset');
const choice = page.getByText(ko['main.request.call.ALLOW'], { exact: true });
await point(choice);
await wait(2_500);
await choice.click();
await wait(1_500);
const send = page.locator('[data-zone="actions"] [data-main]');
await highlight('[data-zone="actions"] [data-main]');
await point(send);
await wait(2_000);
await send.click();
await page.waitForURL(/\/attack\/console/, { timeout: 60_000 });
await guide('clear');

// 2. The same request at the five approaches.
await page.locator('li[data-control="D"]').waitFor({ timeout: 60_000 });
await wait(400);
cue('guide.console.arrive');
for (const control of ['A', 'B', 'C1', 'C2', 'D']) {
  await highlight(`li[data-control="${control}"]`);
  await point(page.locator(`li[data-control="${control}"] > div`).first());
  await wait(1_050);
}

// 3. Contexa holds the response while it decides; the facts on the right light up.
cue('guide.console.hold');
const holdStarted = Date.now();
// Contexa's lane stays framed while it holds the response, then the facts and the risk it weighs.
await highlight('li[data-control="D"]');
await point(page.locator('li[data-control="D"] > div').first());
const decided = Date.now() + RUN_TIMEOUT;
while (Date.now() < decided && (await page.evaluate(() => window.__guide.answeredAt())) === null) {
  await wait(200);
}
// The scene is only true while Contexa still holds the response: a run that held it for less than the scene's first
// sentence (about 2.5 seconds) into the scene is recorded again.
const heldSeconds = ((await page.evaluate(() => window.__guide.answeredAt())) - holdStarted) / 1000;
await wait(1_200);
await highlight('section[aria-labelledby="facts-title"]');
await point(page.locator('section[aria-labelledby="facts-title"] ul'));
await wait(4_500);
await highlight('[class*="_risk_"]');
await wait(2_500);
// The line is read in about 14 seconds; the facts stay framed for the rest of it.
const holdLeft = 14_000 - (Date.now() - holdStarted);
if (holdLeft > 0) {
  await highlight('section[aria-labelledby="facts-title"]');
  await wait(holdLeft);
}

// 4. The bars of the four existing approaches and what they let out.
cue('guide.console.bars');
await highlight('li[data-control="A"] > [class*="_track_"]', 'li[data-control="C2"] > [class*="_track_"]');
await point(page.locator('li[data-control="B"] > [class*="_track_"]'));
await wait(5_500);
await highlight('[class*="_leak_"] > [class*="_counter_"]:first-child');
await point(page.locator('[class*="_leak_"] > [class*="_counter_"]').first());
await wait(5_000);
// The log is read from the stored record once the portal stored the run (the way on opens then), so the next scene
// shows the times that stay.
await page.waitForFunction(
  ([selector, text]) => document.querySelector(selector)?.textContent?.includes(text),
  ['[data-zone="actions"] [data-main]', ko['main.2-2.cta']],
  { timeout: RUN_TIMEOUT },
);
await wait(800);

// 5. The log with each step's real time.
await guide('clear');
await page
  .locator('section[class*="_log_"]')
  .evaluate((element) => element.scrollIntoView({ block: 'center' }));
await wait(1_200);
cue('guide.console.log');
await highlight('section[class*="_log_"]');
await point(page.locator('section[class*="_log_"] [class*="_logAt_"]').first(), 18);
await wait(2_500);
await point(page.locator('section[class*="_log_"] [class*="_logAt_"]').last(), 18);
await wait(6_500);

// 6. The three judgments Contexa can give; this run's stays hidden.
await guide('clear');
await page.evaluate(() => window.scrollTo({ top: 0 }));
await wait(1_000);
cue('guide.console.judgment');
await highlight('li[data-control="D"]');
await guide('chips', true);
await wait(10_000);
await guide('chips', false);
await guide('clear');
const ended = at();
const recordedAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
await guide(
  'end',
  ko['guide.recorded'].replace('{{date}}', recordedAt.slice(0, 10)).replace('{{screens}}', SCREENS),
);
await wait(1_800);
const finished = await run();
const length = at();
const video = page.video();
await context.close();
await browser.close();

if (heldSeconds < 2.5) {
  throw new Error(
    `Contexa held the response only ${heldSeconds}s into the hold scene; nothing was written, record again`,
  );
}
if (cues.map((entry) => entry.key).join() !== script.scenes.join()) {
  throw new Error(`scenes out of order: ${cues.map((entry) => entry.key).join()}`);
}
mkdirSync(OUT, { recursive: true });
copyFileSync(await video.path(), join(OUT, `${ID}.webm`));
// The captions: each scene's line from its start to the next scene's start (the last to the end card), as short lines
// one at a time; the scene times stay in the manifest so e2e/guide-captions.mjs can write them again.
writeFileSync(join(OUT, `${ID}.ko.vtt`), vtt(cues, ended, ko, LINE_LIMIT.ko));
writeFileSync(join(OUT, `${ID}.en.vtt`), vtt(cues, ended, en, LINE_LIMIT.en));
const manifestPath = join(OUT, 'guides.json');
const manifest = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf-8')) : {};
manifest[ID] = {
  file: `${ID}.webm`,
  captions: { ko: `${ID}.ko.vtt`, en: `${ID}.en.vtt` },
  durationSec: Math.round(length * 10) / 10,
  recordedAt,
  screens: SCREENS,
  scenes: cues,
  end: ended,
};
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(
  JSON.stringify(
    {
      cues,
      heldSeconds,
      ended,
      length,
      run: finished && { runId: finished.runId, status: finished.status },
      problems,
    },
    null,
    2,
  ),
);
