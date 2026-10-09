import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Where the statistics went (W4-5): the run statistics gave way to the benchmark, which counts the same runs by the one
 * scoring rule and is checked against the stored rows by quality/w5_benchmark_check.py. The old address and every menu
 * lead there, in Korean and English.
 */
const MESSAGES = {
  ko: JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/ko.json'), 'utf-8')) as Record<string, string>,
  en: JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/en.json'), 'utf-8')) as Record<string, string>,
};

for (const language of ['ko', 'en'] as const) {
  test(`the old statistics address and the menus lead to the benchmark (${language})`, async ({ page }) => {
    const words = MESSAGES[language];
    await page.goto(`/stats?lng=${language}`);
    await expect(page).toHaveURL(/\/benchmark(\?.*)?$/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(words['benchmark.summary.title'] ?? 'missing');

    const menu = page.getByRole('navigation', { name: words['nav.label'] });
    await expect(menu.getByRole('link', { name: words['nav.lab'] })).toHaveAttribute('href', '/lab');
    await expect(menu.getByRole('link', { name: words['nav.benchmark'] })).toHaveAttribute(
      'href',
      '/benchmark',
    );
    const footer = page.getByRole('contentinfo');
    await expect(footer.getByRole('link', { name: words['footer.benchmark'] })).toHaveAttribute(
      'href',
      '/benchmark',
    );
    await expect(footer.getByRole('link', { name: words['footer.lab'] })).toHaveAttribute('href', '/lab');
  });
}
