// The automatic check of the final screen design (docs/showcase/최종화면-구현계획.md FC-1): opens every screen of the
// main flow (src/journey/route.json) on a running portal at the given widths and languages, and judges it:
//   - no sideways scroll, no line ending with one letter alone, no serious or critical axe violation (screenCheck.mjs);
//   - no running text under 16 px (the design's floor, F0-4);
//   - no word of the old column of the term table (설계서 43~45장) on a Korean screen, no Korean word on an English one;
//   - the headline, the intro line and the main button are the screen's own copy (main.{number}.title / intro / cta),
//     where the screen states them in fixed words;
//   - every screen of the main flow has a headline and, but for the live consoles, an intro line (구현계획 NW-12: every
//     screen says at once what it means);
//   - the first view (the first screen's height, what a closed fold holds not counted) stays under 300 characters, but for
//     the screens the plan makes the statistics exception (구현계획 AC-N3; 기획안 R-N3); the count is in each line.
// The console and evidence screens show records by design: their numbers, boxes, run ids and engine codes are not
// limited (FC-1). Each context is a new visitor, so a screen that needs the visitor's run shows its own "send first"
// state, which is judged the same way. Exits 1 when any screen fails.
// With --first-only the rest of the dictionary (dictionarySplit.ts) is never served, as on a first paint before it
// arrives: a main-flow screen must then show no dictionary key in place of its words.
// With --state <file> each context is the visitor of that stored state (one who sent the requests), so the screens show
// their runs: the console, the result, the evidence and the comparisons as a visitor who went through them sees them.
// Usage: node e2e/main-audit.mjs <outDir> [--base <url>] [--widths 1440,390] [--languages ko,en] [--first-only]
//        [--state <storage state json>]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';
import { inspect } from './screenCheck.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
/** The result, the wrap-up, the comparison of every measured run and the third layer of the decision's process (기획안 6.2). */
const STATISTICS = new Set(['2-3', '6-7', '8-1', '8-2', '3-3', '7-3']);
const outDir = args[0];
if (!outDir) {
  console.error('usage: node e2e/main-audit.mjs <outDir> [--base <url>] [--widths 1440,390] [--languages ko,en]');
  process.exit(2);
}
const base = option('--base', 'http://127.0.0.1:19180');
const widths = option('--widths', '1440,390').split(',').map(Number);
const languages = option('--languages', 'ko,en').split(',');
const firstOnly = args.includes('--first-only');
const state = option('--state', null);
// --guides fake lists every guide video of the plan as recorded (the old recording's files under each id), so the audit
// sees the link every screen will carry (가이드영상-제작기획안.md 4절, VP-5). The link's words are a button's: not counted.
const guides = option('--guides', null);
const FAKE_GUIDES = (() => {
  if (guides !== 'fake') {
    return null;
  }
  const recorded = JSON.parse(fs.readFileSync(path.join(here, '..', 'public', 'guides', 'guides.json'), 'utf8')).console;
  const list = JSON.parse(fs.readFileSync(path.join(here, '..', 'src', 'components', 'guide', 'guides.json'), 'utf8'));
  return JSON.stringify(
    Object.fromEntries(
      Object.entries(list)
        .filter(([, entry]) => entry.kind !== 'legacy')
        .map(([id]) => [id, { ...recorded, captionsNarrow: recorded.captions }]),
    ),
  );
})();
// --only 6-,7-0 checks the screens whose numbers start with one of the given beginnings (a recheck after a fix).
const only = option('--only', null)?.split(',').filter(Boolean) ?? null;
const route = JSON.parse(fs.readFileSync(path.join(here, '..', 'src', 'journey', 'route.json'), 'utf8')).filter(
  (screen) => only === null || only.some((beginning) => screen.number.startsWith(beginning)),
);
const books = Object.fromEntries(
  ['ko', 'en'].map((language) => [
    language,
    JSON.parse(fs.readFileSync(path.join(here, '..', 'src', 'i18n', `${language}.json`), 'utf8')),
  ]),
);
// The old column of the term table: words no Korean screen of the main flow shows any more.
const OLD = [
  '계정을 훔친 사람', '진짜 직원', '본인 확인', '규칙 조여 보기', '정상 업무 막음', '업무를 막음', '평소 모습', '시간·건수 제한',
  '웹 방화벽', '로그인·권한 확인', '결재·담당 확인', '판정 자세히 보기', '응답 전에 막기', '다음 요청부터 막기',
  '보류(관리자 검토)', '출처 문장',
];

/** The fixed copy a screen states: its headline, intro and main button; null where the screen picks it from a record. */
function copyOf(screen, book) {
  return {
    title: screen.serverTitle ? null : book[`main.${screen.number}.title`],
    intro: book[`main.${screen.number}.intro`] ?? null,
    main: book[`main.${screen.number}.cta`] ?? null,
  };
}

/** A {{value}} in the copy is the server's value; any text stands in for it. */
function same(shown, copy) {
  if (copy === null || copy === undefined || shown === null) return true;
  const pattern = copy
    .split(/\{\{[^}]+\}\}/)
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('.+?');
  return new RegExp(`^${pattern}$`).test(shown);
}

fs.mkdirSync(outDir, { recursive: true });
const browser = await chromium.launch();
const results = [];
for (const language of languages) {
  const book = books[language];
  for (const width of widths) {
    const context = await browser.newContext({
      viewport: { width, height: width <= 390 ? 844 : 900 },
      locale: language,
      ...(state ? { storageState: state } : {}),
    });
    const page = await context.newPage();
    if (FAKE_GUIDES !== null) {
      await page.route('**/guides/guides.json', (request) =>
        request.fulfill({ contentType: 'application/json', body: FAKE_GUIDES }),
      );
    }
    if (firstOnly) {
      await page.route(/\/assets\/_dictionary-(ko|en)-rest-[^/]+\.js$/, (request) => request.abort());
    }
    // Every key with a dot, longest first, to name a key shown in place of its words.
    const keys = Object.keys(book).filter((key) => key.includes('.')).sort((a, b) => b.length - a.length);
    for (const screen of route) {
      const id = `${screen.number}-${language}-${width}`;
      const fails = [];
      try {
        await page.goto(`${base}${screen.path}?lng=${language}`, { waitUntil: 'load', timeout: 45000 });
        await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
        await page.locator('main h1').first().waitFor({ timeout: 15000 });
        await page.waitForTimeout(1500);
        await page.screenshot({ path: path.join(outDir, `${id}.png`), fullPage: true });
        const checked = await inspect(page);
        if (checked.overflow > 0) fails.push(`sideways scroll ${checked.overflow}px`);
        for (const line of checked.singleLetter) fails.push(`one letter alone '${line}'`);
        for (const violation of checked.serious) fails.push(`axe ${violation.id} ${violation.nodes.join(', ')}`);
        const seen = await page.evaluate(() => {
          const visible = (element) => element.getClientRects().length > 0 && getComputedStyle(element).visibility !== 'hidden';
          const small = [];
          for (const element of document.querySelectorAll('main *, [data-zone="top"] *')) {
            if (!visible(element) || element.closest('[aria-hidden="true"], .visually-hidden')) continue;
            const own = [...element.childNodes].some((node) => node.nodeType === 3 && node.textContent.trim());
            if (!own) continue;
            const size = parseFloat(getComputedStyle(element).fontSize);
            if (size < 15.5) small.push(`${size}px '${element.textContent.trim().slice(0, 24)}'`);
          }
          const clone = document.body.cloneNode(true);
          clone.querySelectorAll('[data-original], dialog:not([open]), script, style, [aria-hidden="true"]').forEach((e) => e.remove());
          document.body.appendChild(clone);
          const text = clone.innerText;
          clone.remove();
          return {
            small: small.slice(0, 5),
            text,
            title: document.querySelector('main h1')?.textContent?.trim() ?? null,
            intro: document.querySelector('[data-zone="title"] [data-guide]')?.textContent?.trim() ?? null,
            main: document.querySelector('[data-zone="actions"] [data-main]')?.textContent?.trim() ?? null,
          };
        });
        for (const small of seen.small) fails.push(`under 16 px ${small}`);
        const first = await page.evaluate(() => {
          const vh = window.innerHeight;
          const header = document.querySelector('header');
          const skipTop = header ? header.getBoundingClientRect().bottom : 0;
          let chars = 0;
          const closedAbove = (el) => { for (let d = el.closest('details:not([open])'); d; d = d.parentElement?.closest('details:not([open])') ?? null) { const s = el.closest('summary'); if (!(s && s.parentElement === d)) return true; } return false; };
          const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
          for (let node = walker.nextNode(); node; node = walker.nextNode()) {
            const text = node.textContent.replace(/\s+/g, ' ').trim();
            const element = node.parentElement;
            if (!text || !element || element.closest('script,style,noscript,[aria-hidden="true"], .visually-hidden')) continue;
            if (closedAbove(element) || element.closest('[data-guide-slot]')) continue;
            const range = document.createRange();
            range.selectNodeContents(node);
            const box = range.getBoundingClientRect();
            if (box.width === 0 || box.height === 0 || box.top >= vh || box.bottom <= skipTop) continue;
            const style = getComputedStyle(element);
            if (style.visibility === 'hidden' || style.display === 'none') continue;
            chars += text.replace(/\s/g, '').length;
          }
          return chars;
        });
        screen.chars = first;
        // The limit is in Korean characters (the plan's unit); the same words take two to two and a half times the letters in
        // English, so an English screen is counted in the line but not failed by it.
        if (language === 'ko' && first >= 300 && !STATISTICS.has(screen.number)) fails.push(`first view ${first} characters (300 or more)`);
        const shownKey = keys.find((key) => seen.text.includes(key));
        if (shownKey) fails.push(`dictionary key shown '${shownKey}'`);
        if (language === 'ko') {
          for (const word of OLD) if (seen.text.includes(word)) fails.push(`old word '${word}'`);
        } else {
          const korean = seen.text.match(/[가-힣]+/g);
          if (korean) fails.push(`korean '${[...new Set(korean)].slice(0, 3).join(' ')}'`);
        }
        const copy = copyOf(screen, book);
        if (!seen.title) fails.push('no headline');
        // The live consoles (T4) show their state in place of an intro line; every other screen says what it is.
        if (!seen.intro && screen.type !== 'T4') fails.push('no intro line');
        // A screen without the visitor's run shows its "send first" state in other words: only a stated copy is held.
        const unsent = [
          book['main.console.notSent'],
          book['main.2-3.intro.none'],
          book['main.4-3.missing.attacker'],
          book['main.4-3.missing.owner'],
          book['main.5-3.intro.none'],
          // docs/agent A7-3: the agent group before the visitor gave the agent the work.
          book['main.6-2.intro.none'],
          book['main.6-3.intro.none'],
          book['main.6-4.intro.none'],
        ].includes(seen.intro ?? '');
        if (!unsent && copy.title && !same(seen.title, copy.title) && !same(seen.title, book[`main.${screen.number}.titlePlain`]) && !same(seen.title, book[`main.${screen.number}.titleCounts`])) {
          fails.push(`title '${seen.title}' != '${copy.title}'`);
        }
        // A screen that sends its own run shows its send button until the run is sent (4-4, FU-3).
        const sending = [
          book['main.request.send'],
          book['main.4-4.sendAgain'],
          // docs/agent A7-3: 6-1 hands the work to the agent; 6-4 waits for the delegating employee's answer.
          book['main.6-1.send'],
          book['main.6-4.waiting'],
        ].includes(seen.main ?? '');
        if (!unsent && !sending && copy.main && seen.main !== null && !seen.main.startsWith(copy.main)) {
          fails.push(`main '${seen.main}' != '${copy.main}'`);
        }
      } catch (error) {
        fails.push(`error ${String(error).slice(0, 160)}`);
      }
      results.push({ id, path: screen.path, chars: screen.chars ?? null, fails });
      console.log(id, `[${screen.chars ?? '-'}]`, fails.length ? `FAIL ${fails.length}: ${fails.slice(0, 4).join('; ')}` : 'PASS');
    }
    await context.close();
  }
}
await browser.close();
fs.writeFileSync(path.join(outDir, 'main-audit.json'), JSON.stringify(results, null, 1));
const failed = results.filter((result) => result.fails.length);
console.log(`done ${results.length} checks, ${failed.length} failing`);
process.exit(failed.length ? 1 : 0);
