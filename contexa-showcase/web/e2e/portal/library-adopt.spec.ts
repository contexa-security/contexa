import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The scenario library (deck p.14) and adopting Contexa (deck p.16) on the real portal: the library plays exactly the
 * published pairs, and the adopt page shows the real coordinates and the Shadow numbers counted from this demo's
 * engine decisions (the same answer of /api/stats).
 */
const COPY = {
  ko: {
    library: '다른 장면',
    adopt: '도입하기',
    play: '기록 보기',
    preparing: '실제 실행 기록 준비 중',
  },
  en: {
    library: 'More scenes',
    adopt: 'Adopt Contexa',
    play: 'See the record',
    preparing: 'Real run being prepared',
  },
} as const;

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
  test(`library and adopt ${language}`, async ({ page }, info) => {
    const copy = COPY[language];
    const pairs = (await (await page.request.get('/api/pairs')).json()) as {
      key: string;
      recorded: boolean;
    }[];
    const recorded = pairs.filter((pair) => pair.recorded).map((pair) => pair.key);

    await page.goto(`/?lng=${language}`);
    await page.getByRole('contentinfo').getByRole('link', { name: copy.library }).click();
    await expect(page).toHaveURL(/\/library$/);
    await expect(page.getByRole('article')).toHaveCount(9);
    const plays = page.getByRole('link', { name: new RegExp(copy.play) });
    await expect(plays).toHaveCount(recorded.length);
    for (const key of recorded) {
      await expect(page.locator(`a[href="/replay/${key}"]`)).toBeVisible();
    }
    await expect(page.getByText(copy.preparing)).toHaveCount(9 - recorded.length);
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `library-${language}-${info.project.name}.png`),
        fullPage: true,
      });
    }

    await page.getByRole('contentinfo').getByRole('link', { name: copy.adopt }).click();
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
