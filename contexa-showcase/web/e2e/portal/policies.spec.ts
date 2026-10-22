import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The privacy notice on the real portal (R7, RO-7): it opens from the menu, the demo asks nothing of the visitor (no
 * banner, no choice), and the notice names every cookie this demo actually set in the browser.
 */
const TITLES = { ko: '개인정보 안내', en: 'Privacy notice' } as const;
const MESSAGES = {
  ko: JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/ko.json'), 'utf-8')) as Record<string, string>,
  en: JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/en.json'), 'utf-8')) as Record<string, string>,
};

async function seriousViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  return results.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map((violation) => violation.id);
}

for (const language of ['ko', 'en'] as const) {
  test(`privacy notice ${language}: from the menu, nothing to answer, every cookie named`, async ({
    page,
    context,
  }) => {
    const words = MESSAGES[language];
    await page.goto(`/?lng=${language}`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(page.getByText(/쿠키 선택|Cookie choice/)).toHaveCount(0);
    await page.locator('header').getByRole('button', { name: words['frame.menu'], exact: true }).click();
    await page.getByRole('dialog').getByRole('link', { name: words['frame.menu.privacy'] }).click();
    await expect(page).toHaveURL(/\/privacy$/);
    await expect(page.getByRole('heading', { level: 1, name: TITLES[language] })).toBeVisible();
    // Nothing to press in the notice itself; the action bar's one way on leads to the start.
    await expect(page.locator('[data-zone="body"]').locator('button, a[href], input')).toHaveCount(0);
    expect(await seriousViolations(page)).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(
      true,
    );
    const named = await page.getByRole('rowheader').allTextContents();
    const set = (await context.cookies()).map((cookie) => cookie.name);
    expect(set.length).toBeGreaterThan(0);
    for (const name of set) {
      expect(named, name).toContain(name);
    }
  });
}
