import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Where the statistics went (W4-5): the run statistics gave way to the benchmark, which counts the same runs by the one
 * scoring rule and is checked against the stored rows by quality/w5_benchmark_check.py. The old address leads there,
 * and so does the menu (R1-3): the top bar holds the terms button (final screen design, 7ab2c1f44) and the menu, whose
 * sheet lists the benchmark; the old footer links are gone. In Korean and English.
 */
const MESSAGES = {
  ko: JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/ko.json'), 'utf-8')) as Record<string, string>,
  en: JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/en.json'), 'utf-8')) as Record<string, string>,
};

for (const language of ['ko', 'en'] as const) {
  test(`the old statistics address and the menu lead to the benchmark (${language})`, async ({ page }) => {
    const words = MESSAGES[language];
    const text = (key: string) => words[key] ?? `missing ${key}`;
    const heading = page.getByRole('heading', { level: 1 });
    const top = page.locator('[data-zone="top"]');

    // The old address is passed on to the benchmark's summary.
    await page.goto(`/stats?lng=${language}`);
    await expect(page).toHaveURL(/\/benchmark(\?.*)?$/);
    await expect(heading).toHaveText(text('bench.chart.summary.title'));
    await expect(top).toContainText(`${text('frame.space.benchmark')} · ${text('bench.r7.view.summary')}`);

    // On a screen of the main flow the top bar has two buttons, the terms and the menu, and nothing else leads to the
    // benchmark.
    await page.goto(`/?lng=${language}`);
    await expect(heading).toHaveText(text('main.1-1.title'));
    await expect(top.getByRole('button')).toHaveCount(2);
    await expect(top.getByRole('button', { name: text('top.terms'), exact: true })).toBeVisible();
    const menuButton = top.getByRole('button', { name: text('frame.menu'), exact: true });
    await expect(menuButton).toHaveAttribute('aria-haspopup', 'dialog');
    await expect(page.getByRole('contentinfo')).toHaveCount(0);
    await expect(page.locator('a[href="/benchmark"]')).toHaveCount(0);

    // The menu's sheet lists the benchmark among the spaces outside the flow; choosing it opens the summary.
    await menuButton.click();
    const sheet = page.getByRole('dialog', { name: text('frame.menu') });
    await expect(sheet).toBeVisible();
    const items = sheet.getByRole('navigation', { name: text('frame.menu') });
    await expect(items.getByRole('link', { name: text('frame.menu.lab') })).toHaveAttribute('href', '/lab');
    const benchmark = items.getByRole('link', { name: text('frame.menu.benchmark') });
    await expect(benchmark).toHaveAttribute('href', '/benchmark');
    await benchmark.click();
    await expect(page).toHaveURL(/\/benchmark$/);
    await expect(sheet).toBeHidden();
    await expect(heading).toHaveText(text('bench.chart.summary.title'));
  });
}
