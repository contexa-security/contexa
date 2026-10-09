import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

/**
 * S11, keyboard only (C-8) on a real portal: the skip link leads into the main area; the concept path goes from its
 * first screen to its last (S12: through the wrap-up to "deeper") with Tab and Enter alone, every focus visibly marked; a window opens from the keyboard,
 * takes the focus to its title, closes with Esc and gives the focus back to its button; on a phone a focused element
 * is never hidden behind the main button fixed at the bottom.
 */
type Dictionary = Record<string, string>;
const ko = JSON.parse(
  readFileSync(new URL('../../src/i18n/ko.json', import.meta.url), 'utf-8'),
) as Dictionary;

function required<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) {
    throw new Error(`missing: ${what}`);
  }
  return value;
}

/** Tab until the screen's main button has the focus; fails when it is never reached. */
async function tabToMain(page: Page) {
  for (let presses = 0; presses < 80; presses += 1) {
    await page.keyboard.press('Tab');
    const reached = await page.evaluate(() => document.activeElement?.hasAttribute('data-main') ?? false);
    if (reached) {
      return;
    }
  }
  throw new Error(`the main button was not reached with Tab on ${page.url()}`);
}

/** Tab until a link with these words has the focus; fails when it is never reached. */
async function tabToLink(page: Page, words: string) {
  for (let presses = 0; presses < 80; presses += 1) {
    await page.keyboard.press('Tab');
    const reached = await page.evaluate(
      (text) => document.activeElement?.tagName === 'A' && (document.activeElement.textContent ?? '').includes(text),
      words,
    );
    if (reached) {
      return;
    }
  }
  throw new Error(`"${words}" was not reached with Tab on ${page.url()}`);
}

/** Whether the focused element shows a focus mark (an outline or a ring). */
async function focusMarked(page: Page) {
  return page.evaluate(() => {
    const element = document.activeElement;
    if (!element) {
      return false;
    }
    const style = getComputedStyle(element);
    return (
      (style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0) || style.boxShadow !== 'none'
    );
  });
}

test('the skip link leads into the main area', async ({ page }) => {
  await page.goto('/intro?route=intro&lng=ko');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: required(ko['app.skipToContent'], 'skip') })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/#main$/);
});

test('the concept path goes to its end with Tab and Enter alone', async ({ page }, info) => {
  test.skip(
    info.project.name === 'webkit' || info.project.name === 'webkit-360',
    'Tab skips links in WebKit',
  );
  test.setTimeout(180_000);
  await page.goto('/intro?route=intro&lng=ko');
  const seen: string[] = [];
  // G1 → G2 (its second layer first) → G3 → where → how → rules → learning → learned → G4 → G5 → try 1, then the
  // concept path's "skip to the next step" past the tries (D-33, no live run is sent) → the six wrap-up screens → deeper.
  for (let screen = 0; screen < 40; screen += 1) {
    const before = page.url();
    // The address changes at once; the next screen's code may still be loading with the previous screen on view, so
    // wait for this screen's own heading before pressing Tab.
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    const path = new URL(before).pathname;
    const sends = await page.evaluate(() => document.querySelector('main [data-main]')?.tagName === 'BUTTON');
    if (path.startsWith('/try/attacker') || path.startsWith('/try/owner') || sends) {
      await tabToLink(page, required(ko['route.skipStep'], 'skip step'));
    } else {
      await tabToMain(page);
    }
    expect(await focusMarked(page), `focus mark on ${before}`).toBe(true);
    const heading = await page.getByRole('heading', { level: 1 }).first().innerText();
    await page.keyboard.press('Enter');
    await expect(page).not.toHaveURL(before);
    // A new screen has its own heading; the concept screen's second layer (?layer=2) is the same screen.
    if (new URL(page.url()).pathname !== path) {
      await expect(page.getByRole('heading', { level: 1 }).first()).not.toHaveText(heading);
    }
    seen.push(new URL(page.url()).pathname + new URL(page.url()).search);
    if (/^\/(lab|benchmark)(\?|$)/.test(new URL(page.url()).pathname)) {
      break;
    }
  }
  const went = seen.join(' → ');
  expect(seen.some((step) => step.startsWith('/try/attacker/scene')), `went through ${went}`).toBe(true);
  expect(seen.some((step) => step.startsWith('/try/summary/recap')), `went through ${went}`).toBe(true);
  expect(new URL(page.url()).pathname, `went through ${went}`).toMatch(/^\/(lab|benchmark)$/);
});

test('a window opens from the keyboard and gives the focus back', async ({ page }) => {
  await page.goto('/intro/approaches?route=intro&lng=ko');
  const first = page
    .getByRole('list', { name: required(ko['approaches.title'], 'title') })
    .getByRole('button')
    .first();
  await first.focus();
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('heading', { level: 2 })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(first).toBeFocused();
});

test('on a phone the focus is never hidden behind the fixed main button', async ({ page }, info) => {
  test.skip(!info.project.name.endsWith('-390') && !info.project.name.endsWith('-360'), 'a phone width only');
  await page.goto('/benchmark/cases?lng=ko');
  await expect(page.locator('main table tbody tr').first()).toBeVisible();
  for (let presses = 0; presses < 45; presses += 1) {
    await page.keyboard.press('Tab');
    const hidden = await page.evaluate(() => {
      const element = document.activeElement;
      const main = document.querySelector('main [data-main]');
      if (!element || !main || element === main || element.closest('main') === null) {
        return null;
      }
      const rect = element.getBoundingClientRect();
      const button = main.getBoundingClientRect();
      return rect.bottom > button.top + 1 && rect.top < button.bottom
        ? (element.textContent ?? '').trim()
        : null;
    });
    expect(hidden, `focused element behind the main button after ${presses + 1} presses`).toBeNull();
  }
});
