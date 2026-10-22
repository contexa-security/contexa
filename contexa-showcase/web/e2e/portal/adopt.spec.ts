import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The adopt space on the real portal (R7, RO-4 and RO-9): opened from the menu, three views walked in order. The first
 * shows the retention of the running settings and the employee's counts of the benchmark, the second the real
 * coordinates, the third what record-only mode would have kept from this demo's judgments (the same answer of
 * /api/stats).
 */
const MESSAGES = {
  ko: JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/ko.json'), 'utf-8')) as Record<string, string>,
  en: JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/en.json'), 'utf-8')) as Record<string, string>,
};

const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

function fill(template: string | undefined, values: Record<string, string>): string {
  return (template ?? 'missing').replace(/\{\{(\w+)\}\}/g, (_, key: string) => values[key] ?? `{{${key}}}`);
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
  test(`adopt ${language}: from the menu through its three views`, async ({ page }, info) => {
    const words = MESSAGES[language];
    const format = new Intl.NumberFormat(language === 'ko' ? 'ko-KR' : 'en-US');
    await page.goto(`/?lng=${language}`);
    await page.locator('header').getByRole('button', { name: words['frame.menu'], exact: true }).click();
    await page.getByRole('dialog').getByRole('link', { name: words['frame.menu.adopt'] }).click();
    await expect(page).toHaveURL(/\/adopt$/);

    const settings = (await (await page.request.get('/api/settings')).json()) as {
      retention: { behaviorDays: number | null; promptOriginalDays: number };
    };
    const kept =
      settings.retention.behaviorDays === null
        ? fill(words['space.r7.adopt.data.keptNoBehavior'], {
            original: format.format(settings.retention.promptOriginalDays),
          })
        : fill(words['space.r7.adopt.data.kept'], {
            behavior: format.format(settings.retention.behaviorDays),
            original: format.format(settings.retention.promptOriginalDays),
          });
    await expect(page.locator('[data-zone="body"]')).toContainText(kept);
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);

    await page.getByRole('link', { name: words['space.r7.adopt.change.next'] }).click();
    await expect(page).toHaveURL(/\/adopt\?step=attach$/);
    await expect(page.locator('pre').first()).toContainText(
      'implementation "ai.ctxa:spring-boot-starter-contexa:0.1.0"',
    );
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);

    await page.getByRole('link', { name: words['space.r7.adopt.attach.next'] }).click();
    await expect(page).toHaveURL(/\/adopt\?step=on$/);
    const stats = (await (await page.request.get('/api/stats')).json()) as {
      engineActions: Record<'ALLOW' | 'CHALLENGE' | 'BLOCK' | 'ESCALATE', number>;
      engineDecisions: number;
    };
    await expect(page.locator('[data-zone="body"]')).toContainText(
      fill(words['space.r7.adopt.watch.counts'], {
        count: format.format(stats.engineDecisions),
        block: format.format(stats.engineActions.BLOCK),
        challenge: format.format(stats.engineActions.CHALLENGE),
        review: format.format(stats.engineActions.ESCALATE),
      }),
    );
    await expect(page.getByRole('link', { name: words['space.r7.adopt.docs'] })).toHaveAttribute(
      'href',
      'https://docs.ctxa.ai',
    );
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
