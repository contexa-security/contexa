import { expect, test, type Page } from '@playwright/test';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * FC-2 on a real portal (최종화면-구현계획 4절): the keyboard alone (Tab, Shift+Tab, Enter, Space, Esc) walks the main
 * flow from the start to its last screen 6-2, the two live sends included (2-1, 4-1), each focus visibly marked and
 * every new screen starting with the focus on its heading; the menu sheet and the decision details open from the
 * keyboard, take the focus and give it back when closed; on a phone (390 px) a focused element is never hidden behind
 * the bottom bar kept in view there, and everything pressable is 44 px or more (a term inside a sentence and a dot of
 * the run matrix, whose runs the case list also opens, are the stated exceptions). Korean in full; English to 2-3.
 *
 * The defects these find are the screens' to fix: the walk and the sweep note them as soft failures and go on, so one
 * run lists them all. It needs a portal with live runs on and no human check, like experience.spec.
 */
type Dictionary = Record<string, string>;
const dictionaries: Record<'ko' | 'en', Dictionary> = {
  ko: JSON.parse(readFileSync(new URL('../../src/i18n/ko.json', import.meta.url), 'utf-8')) as Dictionary,
  en: JSON.parse(readFileSync(new URL('../../src/i18n/en.json', import.meta.url), 'utf-8')) as Dictionary,
};

interface RouteScreen {
  readonly number: string;
  readonly path: string;
  readonly type: string;
}

/** The main flow in order, the same file the screens read (src/journey/route.json). */
const ROUTE = JSON.parse(
  readFileSync(new URL('../../src/journey/route.json', import.meta.url), 'utf-8'),
) as readonly RouteScreen[];
const RUN_TIMEOUT = 180_000;
/** The spaces outside the flow swept on a phone too: the benchmark's six views (docs/showcase/벤치마크-구현계획.md). */
const SPACES = [
  '/benchmark',
  '/benchmark/approaches',
  '/benchmark/cases',
  '/benchmark/judgment',
  '/benchmark/reasoning',
  '/benchmark/limits',
];
/** Where the Korean walk leaves its visitor, so the phone sweep sees the screens with the visitor's own runs. */
const WALKED = 'keyboard-walked-visitor.json';

function required<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) {
    throw new Error(`missing: ${what}`);
  }
  return value;
}

function escape(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** The address of a screen of the flow, with or without a query. */
function at(path: string): RegExp {
  return new RegExp(`^[^?#]*//[^/]+${escape(path)}(\\?.*)?$`);
}

/** The bottom bar's one main button. */
function mainButton(page: Page) {
  return page.locator('[data-zone="actions"] [data-main]');
}

type Target =
  | { readonly kind: 'main' }
  | { readonly kind: 'radio' }
  | { readonly kind: 'choice'; readonly id: string }
  | { readonly kind: 'text'; readonly words: string; readonly within?: string }
  | { readonly kind: 'summary'; readonly words: string }
  | { readonly kind: 'href'; readonly href: string; readonly within?: string };

/** Whether the focused element is the one wanted. */
async function focused(page: Page, target: Target): Promise<boolean> {
  return page.evaluate((wanted) => {
    const element = document.activeElement;
    if (!element || element === document.body) {
      return false;
    }
    const inside = (selector: string | undefined) => !selector || element.closest(selector) !== null;
    switch (wanted.kind) {
      case 'main':
        return element.hasAttribute('data-main') && element.closest('[data-zone="actions"]') !== null;
      case 'radio':
        return element instanceof HTMLInputElement && element.type === 'radio';
      case 'choice':
        return element.tagName === 'A' && element.getAttribute('data-choice') === wanted.id;
      case 'text':
        return (
          (element.tagName === 'BUTTON' || element.tagName === 'A') &&
          (element.textContent ?? '').trim() === wanted.words &&
          inside(wanted.within)
        );
      case 'summary':
        return element.tagName === 'SUMMARY' && (element.textContent ?? '').trim() === wanted.words;
      case 'href':
        return (
          element.tagName === 'A' && element.getAttribute('href') === wanted.href && inside(wanted.within)
        );
    }
  }, target);
}

/** Tab (or Shift+Tab) until the wanted element has the focus; fails naming the screen when it is never reached. */
async function tabTo(page: Page, target: Target, what: string, key: 'Tab' | 'Shift+Tab' = 'Tab') {
  for (let presses = 0; presses < 90; presses += 1) {
    await page.keyboard.press(key);
    if (await focused(page, target)) {
      return;
    }
  }
  throw new Error(`${what} was not reached with ${key} on ${page.url()}`);
}

/** Whether the focused element shows a focus mark; a hidden radio button shows it on its label. */
async function focusMarked(page: Page) {
  return page.evaluate(() => {
    const active = document.activeElement;
    if (!active) {
      return false;
    }
    const element =
      active instanceof HTMLInputElement && active.classList.contains('visually-hidden')
        ? (active.closest('label') ?? active)
        : active;
    const style = getComputedStyle(element);
    return (
      (style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0) || style.boxShadow !== 'none'
    );
  });
}

/** What has the focus, in words for a failure message. */
async function focusName(page: Page) {
  return page.evaluate(() => {
    const element = document.activeElement;
    return element === null || element === document.body
      ? 'the page itself (body)'
      : `${element.tagName.toLowerCase()} "${(element.textContent ?? '').trim().slice(0, 40)}"`;
  });
}

/** A new screen starts with the focus on its own heading (App RouteFocus, WCAG 2.4.3). */
async function arrived(page: Page, path: string) {
  await page.waitForURL(at(path));
  const heading = page.locator('main h1');
  await expect(heading).toBeVisible();
  await expect.soft(heading, `the focus starts on the heading of ${path}`).toBeFocused();
}

/** Tab to the main button, check its words and its focus mark, and press Enter. */
async function pressMain(page: Page, words: string) {
  await expect(mainButton(page)).toHaveText(words);
  await expect(mainButton(page)).toBeEnabled();
  await tabTo(page, { kind: 'main' }, `the main button "${words}"`);
  expect.soft(await focusMarked(page), `focus mark on the main button of ${page.url()}`).toBe(true);
  await page.keyboard.press('Enter');
}

/** After a live wait, the focus is still on the screen, not dropped to the page when the pressed button went away. */
async function focusKept(page: Page, where: string) {
  const name = await focusName(page);
  if (name === 'the page itself (body)') {
    // The screen as the keyboard user is left with it: no element holds the focus.
    const shots = process.env.SHOWCASE_EVIDENCE_DIR ?? test.info().outputPath();
    mkdirSync(shots, { recursive: true });
    await page.screenshot({
      path: join(shots, `focus-lost-${new URL(page.url()).pathname.replace(/\W+/g, '-')}.png`),
    });
  }
  expect.soft(name, `the focus after ${where} on ${page.url()}`).not.toBe('the page itself (body)');
}

/** 2-1 and 4-1: Tab to the first call, Space picks it, Shift+Tab goes back a stop from Send, Enter sends. */
async function predictAndSend(page: Page, text: (key: string) => string, send = 'main.request.send') {
  await tabTo(page, { kind: 'radio' }, 'a judgment to pick');
  expect.soft(await focusMarked(page), `focus mark on the judgment of ${page.url()}`).toBe(true);
  await page.keyboard.press('Space');
  await expect(page.locator('main input[type="radio"]:checked')).toHaveCount(1);
  await expect(mainButton(page)).toHaveText(text(send));
  await expect(mainButton(page)).toBeEnabled();
  await tabTo(page, { kind: 'main' }, 'Send');
  await page.keyboard.press('Shift+Tab');
  await expect(page.locator('[data-zone="actions"] a:not([data-main])')).toBeFocused();
  await page.keyboard.press('Tab');
  expect(await focused(page, { kind: 'main' })).toBe(true);
  expect.soft(await focusMarked(page), `focus mark on Send of ${page.url()}`).toBe(true);
  await page.keyboard.press('Enter');
}

/** The decision details from the keyboard: Enter opens them with the focus on their title, Esc gives it back. */
async function detailWindow(page: Page, opener: Target, what: string) {
  const address = page.url();
  await tabTo(page, opener, what);
  expect.soft(await focusMarked(page), `focus mark on ${what}`).toBe(true);
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/modal=detail/);
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('heading', { level: 2 }).first()).toBeFocused();
  // Tab moves on inside the window, never behind it.
  for (let presses = 0; presses < 3; presses += 1) {
    await page.keyboard.press('Tab');
    expect(await page.evaluate(() => document.activeElement?.closest('dialog[open]') !== null)).toBe(true);
  }
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  // Closing goes back in the history, so the address returns a moment after the window hides.
  await expect(page).toHaveURL(address);
  expect(await focused(page, opener), `the focus back on ${what}`).toBe(true);
}

/**
 * 4-2, 4-4 and 5-2: the real user's and the insider's runs may meet an extra check, whichever way the AI decides. Until the
 * run has ended, Tab to the extra check's buttons as they come (ask for the code, confirm it from the demo inbox) and press
 * Enter, the way a keyboard user answers the check.
 */
async function confirmChecks(page: Page, text: (key: string) => string, done: string) {
  const deadline = Date.now() + 2 * RUN_TIMEOUT;
  while (Date.now() < deadline) {
    if (
      (
        (await mainButton(page)
          .textContent()
          .catch(() => '')) ?? ''
      ).trim() === done
    ) {
      return;
    }
    for (const key of ['try.challenge.useCode', 'try.challenge.requestCode']) {
      const button = page.getByRole('button', { name: text(key), exact: true });
      if (await button.isVisible().catch(() => false)) {
        await tabTo(
          page,
          { kind: 'text', words: text(key), within: '[data-zone="body"]' },
          `the check's ${key}`,
        );
        expect.soft(await focusMarked(page), `focus mark on ${key}`).toBe(true);
        await page.keyboard.press('Enter');
        await page.waitForTimeout(2_000);
        break;
      }
    }
    await page.waitForTimeout(1_000);
  }
  throw new Error(`the run did not end in time on ${page.url()}`);
}

/** The words of a screen's main button on the main flow (최종화면-구현계획 F0-3, NW-6: no cover has a button of its own). */
function mainWords(screen: { readonly number: string }, text: (key: string) => string): string {
  return text(`main.${screen.number}.cta`);
}

/** A card of a choosing screen: Tab to it, check its focus mark and press Enter (구현계획 NW-3). */
async function chooseCard(page: Page, id: string, more: string) {
  // A card kept back (AC-N5: four in view at most) waits under the fold's line: open it from the keyboard first.
  if (
    (await page.locator(`details[data-fold="choose-more"]:not([open]) a[data-choice="${id}"]`).count()) > 0
  ) {
    await tabTo(page, { kind: 'summary', words: more }, `the line that opens more choices on ${page.url()}`);
    expect.soft(await focusMarked(page), 'focus mark on the line of more choices').toBe(true);
    await page.keyboard.press('Enter');
  }
  await tabTo(page, { kind: 'choice', id }, `the card "${id}" of ${page.url()}`);
  expect.soft(await focusMarked(page), `focus mark on the card "${id}" of ${page.url()}`).toBe(true);
  await page.keyboard.press('Enter');
}

/** The way back in the foot of a screen: Tab to the link to `to`, check its focus mark and press Enter. */
async function pressBack(page: Page, to: string) {
  await tabTo(
    page,
    { kind: 'href', href: to, within: '[data-zone="actions"]' },
    `the way back to ${to} from ${page.url()}`,
  );
  expect.soft(await focusMarked(page), `focus mark on the way back to ${to}`).toBe(true);
  await page.keyboard.press('Enter');
}

/**
 * The walk of the main flow by the keyboard, screen by screen (첫화면-선택형-체험-구현계획 3절): the flow is no longer one
 * line, so each step names how its screen is left. `via` is a card ("card:person"), the way back ("back:/person") or the
 * one main button ("main", the default); a screen with an action of its own does it first.
 */
interface Step {
  readonly number: string;
  readonly path: string;
  readonly via?: string;
}
const WALK: readonly Step[] = [
  { number: '1-1', path: '/', via: 'start' },
  { number: 'C-1', path: '/choose', via: 'card:person' },
  { number: 'H-1', path: '/person', via: 'card:attack' },
  { number: '2-1', path: '/attack/request' },
  { number: '2-2', path: '/attack/console' },
  { number: '2-3', path: '/attack/result' },
  { number: '2-4', path: '/attack/reason' },
  { number: 'H-6', path: '/person/next', via: 'card:opposite' },
  { number: '4-1', path: '/normal/request' },
  { number: '4-2', path: '/normal/console' },
  { number: '4-3', path: '/normal/diff' },
  { number: 'H-6', path: '/person/next', via: 'back:/person' },
  { number: 'H-1', path: '/person', via: 'card:insider' },
  { number: '5-1', path: '/insider/request' },
  { number: '5-2', path: '/insider/console' },
  { number: '5-3', path: '/insider/reason' },
  { number: 'H-6', path: '/person/next', via: 'card:deeper' },
  { number: 'D-1', path: '/deeper', via: 'card:evidence' },
  { number: '3-1', path: '/evidence/map' },
  { number: '3-2', path: '/evidence/prompt' },
  { number: '3-3', path: '/evidence/verdict' },
  { number: 'D-1', path: '/deeper', via: 'card:suspected' },
  { number: '4-4', path: '/normal/check' },
  { number: 'D-1', path: '/deeper', via: 'card:rules' },
  { number: '7-1', path: '/compare/rule' },
  { number: '7-2', path: '/compare/change' },
  { number: '7-3', path: '/compare/runs' },
  { number: 'D-1', path: '/deeper', via: 'card:map' },
  { number: '1-2', path: '/intro/map' },
  { number: 'D-1', path: '/deeper', via: 'back:/person/next' },
  { number: 'H-6', path: '/person/next', via: 'card:other' },
  { number: 'A-1', path: '/agent', via: 'card:T5' },
  { number: '6-1', path: '/agent/request' },
  { number: '6-2', path: '/agent/console' },
  { number: '6-7', path: '/agent/result' },
  { number: '6-3', path: '/agent/reason' },
  { number: 'A-6', path: '/agent/next', via: 'card:deeper' },
  { number: 'D-1', path: '/deeper', via: 'card:confirm' },
  { number: '6-4', path: '/agent/confirm' },
  { number: 'D-1', path: '/deeper', via: 'card:end' },
  { number: '6-5', path: '/agent/end' },
  { number: 'D-1', path: '/deeper', via: 'card:burst' },
  { number: '6-6', path: '/agent/burst' },
  { number: 'D-1', path: '/deeper', via: 'back:/agent/next' },
  { number: 'A-6', path: '/agent/next', via: 'main' },
  { number: '8-1', path: '/summary' },
  { number: '8-2', path: '/summary/next' },
];

/**
 * Walks the main flow with the keyboard from the start screen to the `until`-th screen of the walk (the first screen
 * with that number), every step the way a keyboard user would take it, and returns the screen numbers it went through.
 */
async function walk(page: Page, language: 'ko' | 'en', until: string) {
  const words = dictionaries[language];
  const text = (key: string) => required(words[key], `text ${key}`);
  await page.goto(`/?lng=${language}`);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(text('main.1-1.title'));
  const went: string[] = [];
  for (const [index, step] of WALK.entries()) {
    if (index > 0) {
      await arrived(page, step.path);
    }
    went.push(step.number);
    if (step.number === until) {
      return went;
    }
    if (step.via === 'start') {
      await tabTo(
        page,
        { kind: 'text', words: text('main.1-1.cta'), within: 'main' },
        "the landing's way into the demo",
      );
      expect.soft(await focusMarked(page), "focus mark on the landing's way into the demo").toBe(true);
      await page.keyboard.press('Enter');
      continue;
    }
    if (step.via?.startsWith('card:')) {
      await chooseCard(page, step.via.slice('card:'.length), text('choose.more'));
      continue;
    }
    if (step.via?.startsWith('back:')) {
      await pressBack(page, step.via.slice('back:'.length));
      continue;
    }
    if (step.via === 'main' && step.number === 'A-6') {
      await pressMain(page, text('main.A-6.cta'));
      continue;
    }
    switch (step.number) {
      case '2-1':
      case '4-1':
      case '5-1':
        await predictAndSend(page, text);
        break;
      case '2-2':
      case '4-2':
      case '5-2':
        // The console plays by itself; its main button leads on once the judgment is in (the insider's three
        // documents go a minute apart). The owner's and the insider's runs hold the account's mailbox, so an extra check
        // the AI asks for is answered from the keyboard here, as a visitor would.
        if (step.number === '2-2') {
          await expect(mainButton(page)).toHaveText(mainWords(step, text), { timeout: RUN_TIMEOUT });
        } else {
          await confirmChecks(page, text, mainWords(step, text));
        }
        await focusKept(page, 'the live judgment');
        await pressMain(page, mainWords(step, text));
        break;
      case '6-1':
        // docs/agent A7-3: the visitor gives the business agent the work; the agent sends its own requests.
        await predictAndSend(page, text, 'main.6-1.send');
        break;
      case '6-2':
        // The agent works by itself; the way on opens once its requests ended or a confirmation is asked.
        await expect(mainButton(page)).toHaveText(mainWords(step, text), { timeout: RUN_TIMEOUT });
        await focusKept(page, "the agent's work");
        await pressMain(page, mainWords(step, text));
        break;
      case '6-4':
        // The visitor answers as the delegating employee while the run waits for it, from the keyboard.
        if ((await page.getByRole('button', { name: text('main.6-4.approve') }).count()) > 0) {
          await tabTo(
            page,
            { kind: 'text', words: text('main.6-4.approve'), within: '[data-zone="body"]' },
            'Approve',
          );
          expect.soft(await focusMarked(page), 'focus mark on Approve').toBe(true);
          await page.keyboard.press('Enter');
        }
        await expect(mainButton(page)).toHaveText(mainWords(step, text), { timeout: RUN_TIMEOUT });
        await pressMain(page, mainWords(step, text));
        break;
      case '4-4':
        // The real user's case goes live from here; every extra check is confirmed from the demo inbox by keyboard.
        await pressMain(page, text('main.request.send'));
        await confirmChecks(page, text, mainWords(step, text));
        await focusKept(page, 'the checked run');
        await pressMain(page, mainWords(step, text));
        break;
      case '2-3':
        await expect(mainButton(page)).toHaveText(mainWords(step, text));
        await detailWindow(
          page,
          { kind: 'text', words: text('main.2-3.reasons'), within: '[data-zone="body"]' },
          'the result\'s "see the reasons"',
        );
        await pressMain(page, mainWords(step, text));
        break;
      default:
        await pressMain(page, mainWords(step, text));
    }
  }
  return went;
}

test('the skip link leads into the main area', async ({ page }) => {
  await page.goto('/?lng=ko');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await page.keyboard.press('Tab');
  await expect(
    page.getByRole('link', { name: required(dictionaries.ko['app.skipToContent'], 'skip') }),
  ).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/#main$/);
});

test('the main flow from the start to its end with the keyboard alone, the live sends included (ko)', async ({
  page,
  context,
}, info) => {
  test.skip(info.project.name.startsWith('webkit'), 'Tab skips links in WebKit');
  // The live sends include the insider's three documents, a minute apart.
  test.setTimeout(4 * RUN_TIMEOUT + 600_000);
  const text = (key: string) => required(dictionaries.ko[key], `text ${key}`);
  const went = await walk(page, 'ko', '8-2');
  expect(went).toEqual(WALK.map((step) => step.number));

  // The end: its three ways on are reached with Tab, each marked; Shift+Tab goes back to the benchmark, Enter opens it.
  for (const to of ['/adopt', '/benchmark', '/more']) {
    await tabTo(page, { kind: 'href', href: to, within: '[data-zone="body"]' }, `the end's way to ${to}`);
    expect.soft(await focusMarked(page), `focus mark on the way to ${to}`).toBe(true);
  }
  await tabTo(
    page,
    { kind: 'href', href: '/benchmark', within: '[data-zone="body"]' },
    "the end's benchmark",
    'Shift+Tab',
  );
  await page.keyboard.press('Enter');
  await page.waitForURL(at('/benchmark'));
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(text('bench.chart.summary.title'));
  await context.storageState({ path: join(info.project.outputDir, WALKED) });
});

test('the main flow from the start to 2-3 with the keyboard alone (en)', async ({ page }, info) => {
  test.skip(info.project.name.startsWith('webkit'), 'Tab skips links in WebKit');
  test.setTimeout(RUN_TIMEOUT + 240_000);
  const text = (key: string) => required(dictionaries.en[key], `text ${key}`);
  const went = await walk(page, 'en', '2-3');
  expect(went).toEqual(
    WALK.slice(0, WALK.findIndex((step) => step.number === '2-3') + 1).map((s) => s.number),
  );
  await expect(mainButton(page)).toHaveText(text('main.2-3.cta'));
  await tabTo(page, { kind: 'main' }, 'the main button of 2-3');
  expect.soft(await focusMarked(page), 'focus mark on the main button of 2-3').toBe(true);
});

test('the menu sheet opens from the keyboard, holds the focus and gives it back', async ({ page }) => {
  const text = (key: string) => required(dictionaries.ko[key], `text ${key}`);
  await page.goto('/attack/request?lng=ko');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  const menu = page
    .locator('[data-zone="top"]')
    .getByRole('button', { name: text('frame.menu'), exact: true });
  const sheet = page.getByRole('dialog', { name: text('frame.menu') });

  // Enter opens the sheet with the focus on its title; Tab goes through every item without leaving the sheet.
  const menuStop: Target = { kind: 'text', words: text('frame.menu'), within: '[data-zone="top"]' };
  await tabTo(page, menuStop, 'the menu button');
  expect.soft(await focusMarked(page), 'focus mark on the menu button').toBe(true);
  await page.keyboard.press('Enter');
  await expect(sheet).toBeVisible();
  await expect(menu).toHaveAttribute('aria-expanded', 'true');
  await expect(sheet.getByRole('heading', { level: 2 })).toBeFocused();
  const stops = await sheet.locator('a[href], button, [tabindex="0"]').count();
  for (let presses = 0; presses < stops; presses += 1) {
    await page.keyboard.press('Tab');
    expect(await page.evaluate(() => document.activeElement?.closest('dialog[open]') !== null)).toBe(true);
    expect.soft(await focusMarked(page), `focus mark in the sheet after ${presses + 1} presses`).toBe(true);
  }
  // Esc closes it and the focus is back on the menu button.
  await page.keyboard.press('Escape');
  await expect(sheet).toBeHidden();
  await expect(menu).toBeFocused();
  await expect(menu).toHaveAttribute('aria-expanded', 'false');

  // Space opens it again; its close button, pressed with Enter, gives the focus back the same way.
  await page.keyboard.press('Space');
  await expect(sheet).toBeVisible();
  await tabTo(page, { kind: 'text', words: text('modal.close'), within: 'dialog[open]' }, 'the close button');
  await page.keyboard.press('Enter');
  await expect(sheet).toBeHidden();
  await expect(menu).toBeFocused();

  // An item chosen with Enter leads to its space and the sheet closes.
  await page.keyboard.press('Enter');
  await expect(sheet).toBeVisible();
  await tabTo(
    page,
    { kind: 'href', href: '/benchmark', within: 'dialog[open]' },
    'the benchmark in the sheet',
  );
  await page.keyboard.press('Enter');
  await page.waitForURL(at('/benchmark'));
  await expect(sheet).toBeHidden();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(text('bench.chart.summary.title'));

  // On a phone the menu is a sheet from the bottom: the focus goes into it and comes back the same way.
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/attack/request?lng=ko');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await tabTo(page, menuStop, 'the menu button on a phone');
  await page.keyboard.press('Enter');
  await expect(sheet).toBeVisible();
  await expect(sheet.getByRole('heading', { level: 2 })).toBeFocused();
  await page.keyboard.press('Tab');
  expect(await page.evaluate(() => document.activeElement?.closest('dialog[open]') !== null)).toBe(true);
  await page.keyboard.press('Escape');
  await expect(sheet).toBeHidden();
  await expect(menu).toBeFocused();
});

test('the decision details open from the keyboard and Esc gives the focus back', async ({ page }) => {
  // 3-1 lays open the visitor's run or, without one, a measured run of the same case: it always has a record.
  await page.goto('/evidence/map?lng=ko');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await detailWindow(
    page,
    { kind: 'text', words: required(dictionaries.ko['main.3-1.open'], 'text'), within: '[data-zone="body"]' },
    "the first stage's record",
  );
});

test('on a phone the focus never hides behind the fixed bottom bar and every pressable is 44 px or more', async ({
  browser,
}, info) => {
  test.setTimeout(600_000);
  const walked = join(info.project.outputDir, WALKED);
  const context = await browser.newContext({
    viewport: { width: 390, height: 844 },
    ...(existsSync(walked) ? { storageState: walked } : {}),
  });
  const page = await context.newPage();
  const text = (key: string) => required(dictionaries.ko[key], `text ${key}`);
  const shots = process.env.SHOWCASE_EVIDENCE_DIR ?? info.outputPath();
  mkdirSync(shots, { recursive: true });
  // What was found, by element, with the screens it was found on (one screenshot each, the first time).
  const found = new Map<string, string[]>();
  const note = async (what: string, where: string, marker: string | null) => {
    const screens = found.get(what);
    if (screens) {
      screens.push(where);
      return;
    }
    const first = [where];
    found.set(what, first);
    const file = join(shots, `phone-${found.size}.png`);
    // A small target brought into view with the focus on it and a red outline; anything else as the screen is now.
    if (marker) {
      const target = page.locator(`[data-e2e-small="${marker}"]`).first();
      await target.evaluate((element: HTMLElement) => {
        element.focus();
        element.scrollIntoView({ block: 'center' });
        element.style.boxShadow = '0 0 0 3px red';
      });
      await page.screenshot({ path: file });
      await target.evaluate((element: HTMLElement) => {
        element.style.boxShadow = '';
      });
    } else {
      await page.screenshot({ path: file });
    }
    first.push(`(screenshot ${file})`);
  };
  const paths = [...ROUTE.map((screen) => screen.path), ...SPACES];
  try {
    for (const path of paths) {
      await page.goto(`${path}?lng=ko`);
      await expect(page.locator('main h1')).toBeVisible();
      // Let the screen's records arrive, so the sweep sees what a visitor sees.
      await page.waitForTimeout(800);
      const bar = page.locator('[data-zone="actions"]');
      // the landing has no foot: its one button, "데모 시작하기", stands under the text (구현계획 NW-2)
      if (path === '/' && (await bar.count()) === 0) {
        continue;
      }
      if ((await bar.count()) !== 1) {
        await note('no bottom bar', path, null);
        continue;
      }
      if (
        !(await bar.evaluate((element) => ['fixed', 'sticky'].includes(getComputedStyle(element).position)))
      ) {
        await note('the bottom bar is not kept in view', path, null);
      }

      // Tab through the screen: a focused element outside the bar never lies under it.
      for (let presses = 0; presses < 70; presses += 1) {
        await page.keyboard.press('Tab');
        const state = await page.evaluate(() => {
          const element = document.activeElement;
          const fixed = document.querySelector('[data-zone="actions"]');
          if (!element || element === document.body || !fixed) {
            return { done: false, hidden: null };
          }
          if (fixed.contains(element)) {
            const stops = [...fixed.querySelectorAll('a[href], button:not([disabled])')];
            return { done: stops[stops.length - 1] === element, hidden: null };
          }
          if (element.closest('main') === null) {
            return { done: false, hidden: null };
          }
          const rect = element.getBoundingClientRect();
          const cover = fixed.getBoundingClientRect();
          return {
            done: false,
            hidden:
              rect.bottom > cover.top + 1 && rect.top < cover.bottom
                ? {
                    what: `${element.tagName.toLowerCase()} "${(element.textContent ?? '').trim().slice(0, 30)}"`,
                    overlap: Math.round(Math.min(rect.bottom, cover.bottom) - cover.top),
                    bar: Math.round(cover.height),
                  }
                : null,
          };
        });
        if (state.hidden) {
          await note(
            `focus behind the bar: ${state.hidden.what} (${state.hidden.overlap} px under a bar ${state.hidden.bar} px high)`,
            path,
            null,
          );
        }
        if (state.done) {
          break;
        }
      }

      // Everything pressable is 44 px or more; a term inside a sentence is part of the sentence (WCAG 2.5.8).
      await page.evaluate(() => window.scrollTo({ top: 0 }));
      for (const target of await smallTargets(page, 'body')) {
        await note(`under 44 px: ${target.what}`, path, target.marker);
      }
    }

    // The menu sheet on a phone: its items are 44 px or more too.
    await page.goto('/?lng=ko');
    await page
      .locator('[data-zone="top"]')
      .getByRole('button', { name: text('frame.menu'), exact: true })
      .click();
    await expect(page.getByRole('dialog', { name: text('frame.menu') })).toBeVisible();
    for (const target of await smallTargets(page, 'dialog[open]')) {
      await note(`under 44 px: ${target.what}`, 'the menu sheet', target.marker);
    }
  } finally {
    await context.close();
  }
  const report = [...found.entries()].map(([what, screens]) => `${what}: ${screens.join(', ')}`);
  await info.attach('phone-sweep.txt', { body: report.join('\n') || 'none', contentType: 'text/plain' });
  expect.soft(report, 'focus hidden behind the bottom bar, or pressable below 44 px').toEqual([]);
});

/**
 * The pressable elements under 44 px inside `root`, in the rule and with the exceptions of e2e/screenCheck.mjs
 * `mobile`: a radio button counts by its label, and an inline element or a term (data-term) inside a sentence is part
 * of the sentence. Each is marked (data-e2e-small) so its screenshot can find it.
 */
async function smallTargets(page: Page, root: string): Promise<{ what: string; marker: string }[]> {
  return page.evaluate((scope) => {
    const visible = (element: Element) => {
      const style = getComputedStyle(element);
      return element.getClientRects().length > 0 && style.visibility !== 'hidden' && style.opacity !== '0';
    };
    const found = new Map<string, string>();
    const pressable = document
      .querySelector(scope)
      ?.querySelectorAll('a[href], button, summary, select, input, textarea, [role="tab"], [tabindex="0"]');
    for (const control of pressable ?? []) {
      const label = control.tagName === 'INPUT' ? control.closest('label') : null;
      const element = label ?? control;
      if (control.tagName === 'INPUT' && !label && control.classList.contains('visually-hidden')) continue;
      if (!visible(element) || element.closest('dialog:not([open])')) continue;
      if (getComputedStyle(element).display === 'inline' || element.hasAttribute('data-term')) continue;
      // A dot of the run matrix opens its run; the case list opens the same runs with full-size targets (WCAG 2.5.8).
      if (element.hasAttribute('data-dot')) continue;
      const rect = element.getBoundingClientRect();
      if (rect.width === 0) continue;
      if (rect.height < 43.5 || rect.width < 43.5) {
        const what = `${element.tagName.toLowerCase()} ${Math.round(rect.width)}x${Math.round(rect.height)} "${(element.textContent ?? '').trim().slice(0, 30)}"`;
        if (!found.has(what)) {
          const marker = String(found.size + 1);
          element.setAttribute('data-e2e-small', marker);
          found.set(what, marker);
        }
      }
    }
    return [...found.entries()].map(([what, marker]) => ({ what, marker }));
  }, root);
}
