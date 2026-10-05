import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Deck p.15 on the real portal: after the vote and both scenes, the end screen shows the result the server scored
 * (the same answer of /api/results for this visitor), one next action, and a share card made from the result values
 * only; in Korean and English, without horizontal scrolling or serious accessibility violations.
 */
const COPY = {
  ko: {
    block: '차단한다',
    next: '다음',
    results: '결과 보기',
    share: '결과 공유',
    carried: '첫 질문의 판단을',
  },
  en: {
    block: 'Block it',
    next: 'Next',
    results: 'See your result',
    share: 'Share the result',
    carried: 'Your answer',
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
    await page.goto(`/?lng=${language}`);
    await page.getByRole('button', { name: copy.block }).click();
    await expect(page).toHaveURL(/\/replay\/A3$/);
    await page.getByRole('button', { name: copy.next, exact: true }).click();
    await page.getByRole('link', { name: copy.results }).click();
    await expect(page).toHaveURL(/\/end\/A3$/);

    const result = (await (await page.request.get('/api/results/A3')).json()) as {
      mine: Score | null;
      contexa: Score;
    };
    expect(result.mine).not.toBeNull();
    const values = page.locator('dl dd');
    await expect(values).toHaveText([
      `${result.mine?.hits}/${result.mine?.total}`,
      `${result.contexa.hits}/${result.contexa.total}`,
    ]);
    await expect(page.getByText(copy.carried)).toBeVisible();
    await expect(page.getByRole('link', { name: /explore|직접 해보기|try it/i }).first()).toHaveAttribute(
      'href',
      '/explore',
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
