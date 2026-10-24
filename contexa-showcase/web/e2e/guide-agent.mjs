// Guide video of the business agent group (docs/agent A7-4, 가이드영상-계획.md 6절): how to give the business agent
// work. Records the real stack at 1440 x 900 in Korean: the 6-1 work, one live send of the agent case, the 6-2 rows and
// the 6-3 cards. Drawn over the site are only a highlight frame, the pointer, the meanings of the delegating person's
// two answers in the last scene and, wherever Contexa's result of this case would show, "send it yourself" in its place
// (plan principle 2: the 6-2 Contexa column and the lines under the rows, the 6-3 difference, judgment and intro; 6-4 is
// not recorded). The confirmation the run waits for is left unanswered and ended after the recording, so no decision
// model is called. Writes public/guides/agent.webm, agent.ko.vtt, agent.en.vtt and the agent entry of
// public/guides/guides.json. One live send (the agent case; the agent's light model only).
// Usage (web folder): node e2e/guide-agent.mjs [base url]
import { chromium } from '@playwright/test';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LINE_LIMIT, vtt } from './guideCaptions.mjs';

const base = process.argv[2] ?? 'http://127.0.0.1:19180';
const ko = JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8'));
const en = JSON.parse(readFileSync('src/i18n/en.json', 'utf-8'));
const script = JSON.parse(readFileSync('src/components/guide/guides.json', 'utf-8')).agent;
const OUT = 'public/guides';
const ID = 'agent';
const SCREENS = 'v4';
const RUN_TIMEOUT = 240_000;
const SIZE = { width: 1440, height: 900 };

/** The words drawn over the site, all from the Korean dictionary the recorded screens use. */
const overlayWords = {
  hidden: ko['guide.hidden'],
  answers: [
    { kind: 'APPROVE', name: ko['main.6-4.approve'], meaning: ko['guide.agent.approveMeaning'] },
    { kind: 'REJECT', name: ko['main.6-4.reject'], meaning: ko['guide.agent.rejectMeaning'] },
  ],
};

/**
 * The layer over the site. It never changes the page's own elements: a style hides Contexa's result of this case
 * wherever it would show (pure CSS, so no frame shows it), and a few fixed boxes are added.
 */
function overlay(words) {
  const style = document.createElement('style');
  style.textContent = `
    html[data-guide-recording] main table tbody td:last-child > *,
    html[data-guide-recording] section[aria-labelledby="agent-asked-line"],
    html[data-guide-recording] section[aria-labelledby="agent-analysis"],
    html[data-guide-recording] section[aria-labelledby="agent-answer"],
    html[data-guide-recording] section[aria-labelledby="fact-difference"] > p,
    html[data-guide-recording] section[aria-labelledby="judgment"],
    html[data-guide-recording] section[aria-labelledby="existing"] li:last-child > :last-child,
    html[data-guide-recording][data-guide-page="reason"] [data-zone="title"] [data-guide],
    html[data-guide-recording] [data-zone="title"] [aria-haspopup="dialog"] { visibility: hidden !important; }
    .guide-hidden, #guide-box, #guide-pointer, #guide-answers, #guide-end { position: fixed; z-index: 2147483647; pointer-events: none; }
    #guide-box { border: 3px solid #f2c14e; border-radius: 12px; box-shadow: 0 0 0 9999px rgb(4 8 16 / 38%);
      transition: all 260ms ease; opacity: 0; }
    #guide-pointer { inline-size: 22px; block-size: 22px; margin: -11px 0 0 -11px; border-radius: 50%;
      background: rgb(242 193 78 / 55%); border: 2px solid #fff; transition: transform 120ms; }
    #guide-pointer[data-down] { transform: scale(0.7); }
    .guide-hidden { display: none; padding: 8px 16px; border-radius: 999px; background: #f2c14e; color: #171206;
      font: 600 17px/1.3 var(--font-sans); transform: translate(-50%, -50%); white-space: nowrap; }
    .guide-hidden[data-on] { display: block; }
    #guide-answers { display: none; flex-direction: column; gap: 14px; padding: 20px 24px; border-radius: 14px;
      background: #0f1a2e; border: 1px solid #f2c14e; color: #e8edf5; font: 18px/1.4 var(--font-sans);
      left: 50%; top: 50%; transform: translate(-50%, -50%); }
    #guide-answers[data-on] { display: flex; }
    #guide-answers div { display: flex; gap: 16px; align-items: center; }
    #guide-answers b { min-inline-size: 88px; padding: 6px 14px; border-radius: 10px; text-align: center; color: #0b1220; }
    #guide-answers b[data-kind="APPROVE"] { background: #f2c14e; }
    #guide-answers b[data-kind="REJECT"] { background: #c9d2e3; }
    #guide-end { inset: 0; display: none; place-items: center; background: #0b1220; color: #e8edf5;
      font: 600 24px/1.5 var(--font-sans); text-align: center; }
    #guide-end[data-on] { display: grid; }
  `;
  const add = () => {
    if (document.getElementById('guide-box')) return;
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
    const hiddenColumn = make('guide-hidden-column', words.hidden);
    const hiddenDifference = make('guide-hidden-difference', words.hidden);
    hiddenColumn.className = 'guide-hidden';
    hiddenDifference.className = 'guide-hidden';
    const answers = make('guide-answers');
    for (const answer of words.answers) {
      const row = document.createElement('div');
      const name = document.createElement('b');
      name.dataset.kind = answer.kind;
      name.textContent = answer.name;
      const meaning = document.createElement('span');
      meaning.textContent = answer.meaning;
      row.append(name, meaning);
      answers.appendChild(row);
    }
    make('guide-end');
    let targets = [];
    window.__guide = {
      highlight(selectors) {
        targets = selectors;
      },
      clear() {
        targets = [];
      },
      answers(on) {
        answers.toggleAttribute('data-on', on);
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
      document.documentElement.toggleAttribute('data-guide-page', false);
      if (location.pathname === '/agent/reason')
        document.documentElement.setAttribute('data-guide-page', 'reason');
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
      // "Send it yourself" over Contexa's column of the rows and over the difference the engine named.
      const place = (label, element) => {
        label.toggleAttribute('data-on', element !== null);
        if (element) {
          const rect = element.getBoundingClientRect();
          label.style.left = `${rect.left + rect.width / 2}px`;
          label.style.top = `${rect.top + rect.height / 2}px`;
        }
      };
      const cells = [...document.querySelectorAll('main table tbody td:last-child')];
      place(hiddenColumn, cells.length > 0 ? cells[0] : null);
      place(hiddenDifference, document.querySelector('section[aria-labelledby="fact-difference"]'));
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  };
  if (document.body) add();
  else document.addEventListener('DOMContentLoaded', add);
}

const browser = await chromium.launch();
const raw = mkdtempSync(join(tmpdir(), 'guide-agent-'));
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
async function point(locator) {
  const box = await locator.boundingBox();
  if (box) {
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 18 });
  }
}

// 1. The work given: the delegation record's objective, scope and period.
await page.setContent('<html style="background:#070c18"></html>');
await page.goto(`${base}/agent/request`, { waitUntil: 'networkidle' });
await page.getByText(ko['main.6-1.call.ALLOW'], { exact: true }).waitFor();
await wait(600);
cue('guide.agent.work');
await highlight('section[aria-labelledby="agent-work"]');
await point(page.locator('section[aria-labelledby="agent-work"] dl'));
await wait(9_000);

// 2. The employee's instruction, the call, and handing the work to the agent.
cue('guide.agent.send');
await highlight('section[aria-labelledby="agent-asked"]');
await point(page.locator('section[aria-labelledby="agent-asked"] p').first());
await wait(5_000);
await highlight('fieldset');
const choice = page.getByText(ko['main.6-1.call.ALLOW'], { exact: true });
await point(choice);
await wait(2_000);
await choice.click();
await wait(1_200);
const send = page.locator('[data-zone="actions"] [data-main]');
await highlight('[data-zone="actions"] [data-main]');
await point(send);
await wait(2_000);
await send.click();
await page.waitForURL(/\/agent\/console/, { timeout: 60_000 });
await guide('clear');

// 3. One row per request the agent sent, with the five approaches' answers.
await page.locator('main table tbody tr').first().waitFor({ timeout: RUN_TIMEOUT });
await wait(800);
cue('guide.agent.rows');
await highlight('main table');
await point(page.locator('main table thead th').first());
await wait(3_000);
for (const column of [2, 3, 4, 5, 6]) {
  await point(page.locator(`main table thead th:nth-child(${column})`));
  await wait(1_300);
}
// The way on opens once the agent's requests ended (or a confirmation is asked).
await page.waitForFunction(
  ([selector, text]) => document.querySelector(selector)?.textContent?.includes(text),
  ['[data-zone="actions"] [data-main]', ko['main.6-2.cta']],
  { timeout: RUN_TIMEOUT },
);
await wait(1_500);

// 4. The three cards of the next screen: the work given, the request sent, and the engine's difference (hidden).
await guide('clear');
await page.locator('[data-zone="actions"] [data-main]').click();
await page.waitForURL(/\/agent\/reason/, { timeout: 60_000 });
await page.locator('section[aria-labelledby="fact-work"]').waitFor({ timeout: 60_000 });
await wait(1_000);
cue('guide.agent.reason');
await highlight('section[aria-labelledby="fact-work"]');
await point(page.locator('section[aria-labelledby="fact-work"] dl'));
await wait(3_500);
await highlight('section[aria-labelledby="fact-request"]');
await point(page.locator('section[aria-labelledby="fact-request"] dl'));
await wait(3_500);
await highlight('section[aria-labelledby="fact-difference"]');
await point(page.locator('section[aria-labelledby="fact-difference"]'));
await wait(4_000);

// 5. The delegating person's two answers; this run's own stays hidden.
await guide('clear');
cue('guide.agent.answer');
await guide('answers', true);
await wait(11_000);
await guide('answers', false);
const ended = at();
const recordedAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
await guide(
  'end',
  ko['guide.recorded'].replace('{{date}}', recordedAt.slice(0, 10)).replace('{{screens}}', SCREENS),
);
await wait(1_800);
const length = at();
// The confirmation the run waits for is left unanswered: the run ends without the request sent again.
const before = await run();
await page.evaluate(() => {
  const token = document.cookie
    .split('; ')
    .find((entry) => entry.startsWith('XSRF-TOKEN='))
    ?.split('=')[1];
  return fetch('/api/live/runs/current/abandon', {
    method: 'POST',
    headers: token ? { 'X-XSRF-TOKEN': decodeURIComponent(token) } : {},
  });
});
const video = page.video();
await context.close();
await browser.close();

if (cues.map((entry) => entry.key).join() !== script.scenes.join()) {
  throw new Error(`scenes out of order: ${cues.map((entry) => entry.key).join()}`);
}
mkdirSync(OUT, { recursive: true });
copyFileSync(await video.path(), join(OUT, `${ID}.webm`));
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
    { cues, ended, length, run: before && { runId: before.runId, status: before.status }, problems },
    null,
    2,
  ),
);
