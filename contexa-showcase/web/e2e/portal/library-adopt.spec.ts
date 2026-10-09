import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Where the scenario library went (W4-5) and adopting Contexa (deck p.16) on the real portal: the footer leads to the
 * lab, the old library address leads there too, and the adopt page shows the real coordinates and the Shadow numbers
 * counted from this demo's engine decisions (the same answer of /api/stats).
 */
const MESSAGES = {
  ko: JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/ko.json'), 'utf-8')) as Record<string, string>,
  en: JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/en.json'), 'utf-8')) as Record<string, string>,
};

const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

async function seriousViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  return results.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map((violation) => violation.id);
}

async function noHorizontalScroll(page: Page) {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
}

for (const language of ['ko', 'en'] as const) {
  test(`lab and adopt ${language}`, async ({ page }, info) => {
    const words = MESSAGES[language];
    await page.goto(`/?lng=${language}`);
    await page.getByRole('contentinfo').getByRole('link', { name: words['footer.lab'] }).click();
    await expect(page).toHaveURL(/\/lab$/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(words['labEntrance.title'] ?? 'missing');
    // The old library address leads to the lab, which opens every designed case (W4-5).
    await page.goto(`/library?lng=${language}`);
    await expect(page).toHaveURL(/\/lab(\?.*)?$/);

    await page.getByRole('contentinfo').getByRole('link', { name: words['footer.adopt'] }).click();
    await expect(page).toHaveURL(/\/adopt$/);
    await expect(page.locator('pre').first()).toContainText(
      'implementation "ai.ctxa:spring-boot-starter-contexa:0.1.0"',
    );
    const stats = (await (await page.request.get('/api/stats')).json()) as {
      engineActions: Record<'ALLOW' | 'CHALLENGE' | 'BLOCK' | 'ESCALATE', number>;
    };
    const format = new Intl.NumberFormat(language === 'ko' ? 'ko-KR' : 'en-US');
    await expect(page.locator('dl dd')).toHaveText([
      format.format(stats.engineActions.BLOCK),
      format.format(stats.engineActions.CHALLENGE),
      format.format(stats.engineActions.ESCALATE),
    ]);
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `adopt-${language}-${info.project.name}.png`),
        fullPage: true,
      });
    }
  });
}
