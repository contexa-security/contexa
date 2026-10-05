import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * P5-BE-01 and the statistics part of P5-FE-01 on a real portal: the page shows the numbers the server counted from
 * the stored runs (the same answer of /api/stats, cached for a minute), in Korean and English, without horizontal
 * scrolling and without serious accessibility violations. The server count itself is checked against the raw rows
 * by .contexa-verify/showcase/p5-stats-check.py.
 */
const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

interface Stats {
  readonly runs: { readonly completed: number };
  readonly layers: readonly {
    readonly control: string;
    readonly threat: { readonly runs: number; readonly leaked: number; readonly stopped: number };
    readonly normal: { readonly runs: number; readonly challenged: number; readonly blocked: number };
  }[];
}

function cell(part: number, whole: number) {
  return whole > 0 ? `${part}/${whole} (${Math.round((part / whole) * 100)}%)` : '—';
}

async function seriousViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  return results.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map((violation) => violation.id);
}

for (const language of ['ko', 'en'] as const) {
  test(`statistics page shows the server count (${language})`, async ({ page }, testInfo) => {
    await page.goto(`/stats?lng=${language}`);
    const stats = (await (await page.request.get('/api/stats')).json()) as Stats;
    const format = new Intl.NumberFormat(language === 'ko' ? 'ko-KR' : 'en-US');

    await expect(page.getByRole('heading', { level: 1 })).toHaveText(
      language === 'ko' ? '수행 통계' : 'Execution statistics',
    );
    await expect(page.locator('dl dd').first()).toHaveText(format.format(stats.runs.completed));
    for (const layer of stats.layers) {
      await expect(page.locator(`tr[data-control="${layer.control}"] td [data-part="value"]`)).toHaveText([
        cell(layer.threat.leaked, layer.threat.runs),
        cell(layer.threat.stopped, layer.threat.runs),
        cell(layer.normal.blocked, layer.normal.runs),
        cell(layer.normal.challenged, layer.normal.runs),
      ]);
    }

    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow, 'horizontal page scroll').toBeLessThanOrEqual(0);
    expect(await seriousViolations(page)).toEqual([]);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `stats-${language}-${testInfo.project.name}.png`),
        fullPage: true,
      });
    }
  });
}
