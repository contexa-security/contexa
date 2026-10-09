import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

/**
 * Act 2 on the real portal (screen design v2.3, 7.2): try 2 sends one real export as the real employee through the
 * visitor's own gate (answering the identity check in place when Contexa asks), then the published rules, the
 * identity check step, the follow-up map and the act-end screen. Every value on screen is checked against the portal's
 * own answer. It needs a portal with live runs of A3T on and limits high enough for one run per language.
 */
const MESSAGES = {
  ko: JSON.parse(readFileSync(new URL('../../src/i18n/ko.json', import.meta.url), 'utf-8')) as Record<
    string,
    string
  >,
  en: JSON.parse(readFileSync(new URL('../../src/i18n/en.json', import.meta.url), 'utf-8')) as Record<
    string,
    string
  >,
};
const RUN_TIMEOUT = 180_000;
const CONTROLS = ['A', 'B', 'C1', 'C2', 'D'] as const;

interface RunScore {
  readonly business: Readonly<Record<string, { readonly result: string; readonly exposedItems: number }>>;
  readonly correct: Readonly<Record<string, boolean>>;
}

test.describe.configure({ mode: 'serial' });

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

async function noHorizontalScroll(page: Page) {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
}

function format(template: string, values: Readonly<Record<string, string | number>>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => String(values[key] ?? ''));
}

function items(value: number, language: 'ko' | 'en'): string {
  return value.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US');
}

const api = (page: Page, path: string) =>
  page.evaluate((target) => fetch(target).then((r) => (r.ok ? r.json() : null)), path);

for (const language of ['ko', 'en'] as const) {
  const m = MESSAGES[language];

  test(`try 2 sends one live run and every act 2 screen shows its records (${language})`, async ({ page }) => {
    test.setTimeout(RUN_TIMEOUT + 180_000);
    await page.goto(`/try/owner/scene?lng=${language}`);
    const options = await api(page, '/api/lab/options');
    const a3t = options.cases.find((candidate: { key: string }) => candidate.key === 'A3T');
    const count = a3t.requests[0].items as number;
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(
      format(m['e2.scene.title'] ?? '', { items: items(count, language) }),
    );
    await expect(page.getByText(m['role.changed'] ?? '')).toBeVisible();

    await page.goto(`/try/owner/compare?lng=${language}`);
    const before = await api(page, '/api/live/before/A3T?step=1');
    if (before?.comparison) {
      await expect(page.getByRole('heading', { level: 1 })).toHaveText(
        format(m['e2.compare.title'] ?? '', {
          usual: before.comparison.departureCount,
          company: before.comparison.companyAdverseCount,
        }),
      );
    }

    await page.goto(`/try/owner/predict?lng=${language}`);
    await page
      .getByText(m['e1.predict.ALLOW'] ?? '', { exact: true })
      .first()
      .click();
    await page
      .locator('fieldset', { hasText: m['e2.predict.numberRule'] ?? '' })
      .getByText(m['e2.predict.numberRule.STOP'] ?? '', { exact: true })
      .click();
    await page
      .getByRole('button', { name: format(m['e1.predict.send'] ?? '', { items: items(count, language) }) })
      .click();
    await page.waitForURL(/\/try\/owner\/run/);
    // When Contexa asks the real employee for a check, they answer it in place with the code in their inbox.
    const next = page.getByRole('link', { name: m['e1.next.result'] ?? '' });
    const deadline = Date.now() + RUN_TIMEOUT;
    while (Date.now() < deadline && !(await next.count())) {
      const request = page.getByRole('button', { name: m['try.challenge.requestCode'] ?? '' });
      if (await request.count()) {
        await request.click();
      }
      const use = page.getByRole('button', { name: m['try.challenge.useCode'] ?? '' });
      if (await use.count()) {
        await use.click();
      }
      await page.waitForTimeout(1000);
    }
    await expect(next).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);

    const live = await api(page, '/api/live/runs/current');
    const score = (await api(page, `/api/runs/${live.runId}/score`)) as RunScore;
    await page.goto(`/try/owner/result?lng=${language}`);
    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(CONTROLS.length);
    for (const [index, control] of CONTROLS.entries()) {
      const right = score.correct[control];
      const cell = rows.nth(index).locator('td').nth(1);
      await expect(cell).toContainText(
        right === undefined ? (m['mark.neither'] ?? '') : right ? (m['mark.right'] ?? '') : (m['mark.wrong'] ?? ''),
      );
    }
    const journey = await api(page, '/api/journey');
    const call = journey.predictions.find((prediction: { caseKey: string }) => prediction.caseKey === 'A3T');
    expect(call?.call.engine).toBe('ALLOW');
    expect(call?.call.numberRule).toBe('STOP');

    await page.goto(`/try/owner/reason?lng=${language}`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

    await page.goto(`/intro/how/rules?lng=${language}`);
    for (const verdict of ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK']) {
      await expect(page.getByText(m[`gRules.verdict.${verdict}`] ?? '')).toBeVisible();
    }
    const teasers = await api(page, '/api/teasers');
    const promptRun = teasers.teasers.find((teaser: { key: string }) => teaser.key === 'G_HOW_LINES').source.ref;
    const anatomy = await api(page, `/api/runs/${promptRun}/steps/1/anatomy`);
    const lines = anatomy.promptLines.systemPhysical as number;
    await page.getByRole('button', { name: format(m['gRules.original'] ?? '', { lines }) }).click();
    await expect(page.locator('dialog ol li')).toHaveCount(lines);
    await page.keyboard.press('Escape');
    expect(await seriousViolations(page)).toEqual([]);

    await page.goto(`/try/owner/after?lng=${language}`);
    const checked = live.challenge?.stage === 'DONE';
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(
      m[checked ? 'e2.check.title' : 'e2.check.noneTitle'] ?? '',
    );

    await page.goto(`/try/follow?lng=${language}`);
    const stats = await api(page, '/api/stats');
    await expect(page.locator('main')).toContainText(
      format(m['follow.count'] ?? '', { n: items(stats.engineActions.ALLOW, language) }),
    );
    expect(await seriousViolations(page)).toEqual([]);
    await page.getByRole('link', { name: m['e2.next.end'] ?? '' }).click();
    await page.waitForURL(/\/try\/follow\/end/);
    await expect(page.locator('section[aria-labelledby="act-end-2"]')).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
  });
}
