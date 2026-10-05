import { expect, test } from '@playwright/test';

/**
 * P2-FE-05: the shared components on the design mock still render as they did at the P0 gate. A difference above
 * one percent of the pixels fails; the diff image is written next to the test results.
 */
const VIEWPORTS = [
  { name: 'desktop-1440', width: 1440, height: 900 },
  { name: 'tablet-768', width: 768, height: 1024 },
  { name: 'mobile-390', width: 390, height: 844 },
] as const;

for (const viewport of VIEWPORTS) {
  for (const scheme of ['dark', 'light'] as const) {
    for (const language of ['ko', 'en'] as const) {
      test(`design mock ${viewport.name} ${scheme} ${language} matches P0`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: scheme });
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await page.goto(`/design?lng=${language}`);
        await expect(page.getByRole('heading', { name: 'Contexa' })).toBeVisible();
        await page.evaluate(() => document.fonts.ready);
        expect(await page.screenshot({ fullPage: true })).toMatchSnapshot(
          `design-${viewport.name}-${scheme}-${language}.png`,
          { maxDiffPixelRatio: 0.01 },
        );
      });
    }
  }
}
