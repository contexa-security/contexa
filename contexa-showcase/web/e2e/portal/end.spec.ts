import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Deck p.15 on the real portal: after both scenes of a recorded replay (opened from the library; the first screen is
 * the hands-on experience and asks for no vote), the end screen shows the result the server scored (the same answer of
 * /api/results for this visitor), one next action, and a share card made from the result values only; in Korean and
 * English, without horizontal scrolling or serious accessibility violations.
 */
const COPY = {
  ko: {
    next: '다음',
    results: '결과 보기',
    share: '결과 공유',
  },
  en: {
    next: 'Next',
    results: 'See your result',
    share: 'Share the result',
  },
} as const;

const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

interface Score {
  readonly hits: number;
  readonly total: number;
}

async function seriousViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  return results.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map(
      (violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(' ')).join(', ')}`,
    );
}

for (const language of ['ko', 'en'] as const) {
  test(`end screen ${language}: server result, one next action, share card`, async ({ page }, info) => {
    const copy = COPY[language];
    await page.goto(`/replay/A3?lng=${language}`);
    await page.getByRole('button', { name: copy.next, exact: true }).click();
    await page.getByRole('link', { name: copy.results }).click();
    await expect(page).toHaveURL(/\/end\/A3$/);

    const result = (await (await page.request.get('/api/results/A3')).json()) as {
      mine: Score | null;
      contexa: Score;
    };
    expect(result.mine).toBeNull();
    await expect(page.locator('dl dd')).toHaveText([`${result.contexa.hits}/${result.contexa.total}`]);
    await expect(page.getByRole('main').getByRole('link', { name: /직접 해보기|try it/i }).first()).toHaveAttribute(
      'href',
      '/',
    );
    expect(await seriousViolations(page)).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(
      true,
    );

    await page.getByRole('button', { name: copy.share }).click();
    const card = page.locator('img[src*="/card.png"]');
    await expect(card).toBeVisible();
    // The image may still be loading right after it becomes visible.
    await expect
      .poll(() => card.evaluate((image: HTMLImageElement) => (image.complete ? image.naturalWidth : 0)))
      .toBe(1200);
    await expect(page.locator('#share-url')).toHaveValue(/\/s\/[A-Za-z0-9]{10}$/);
    expect(await seriousViolations(page)).toEqual([]);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `end-${language}-${info.project.name}.png`),
        fullPage: true,
      });
    }
  });
}
