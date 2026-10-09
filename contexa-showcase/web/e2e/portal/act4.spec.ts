import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

/**
 * Act 4 on the real portal (screen design v2.3, 7.4): the five approaches with their published settings, where they
 * sit, the rules' dilemma, what the visitor did, the understanding check scored by the server, the core value and what
 * changes with adoption. The visitor first sends try 1 so "what you did" has a run of their own. Every value on screen
 * is checked against the portal's own answer.
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
const RUN_TIMEOUT = 240_000;

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

function seconds(ms: number): string {
  return ms >= 1000 ? (ms / 1000).toFixed(1) : (ms / 1000).toFixed(2);
}

function escape(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const api = (page: Page, path: string) =>
  page.evaluate((target) => fetch(target).then((r) => (r.ok ? r.json() : null)), path);

interface Score {
  readonly control: string;
  readonly falseBlock: { readonly hits: number; readonly total: number };
  readonly friction: { readonly hits: number };
  readonly stopped: { readonly hits: number };
  readonly missed: number;
}

interface TeaserItem {
  readonly key: string;
  readonly values: Record<string, unknown>;
  readonly holds: boolean | null;
}

for (const language of ['ko', 'en'] as const) {
  const m = MESSAGES[language];

  test(`act 4 shows the measured comparison and the visitor's own runs (${language})`, async ({ page }) => {
    test.setTimeout(RUN_TIMEOUT + 240_000);

    // Try 1 sent without a call, so "what you did" has the visitor's own run.
    await page.goto(`/try/attacker/predict?lng=${language}`);
    const options = await api(page, '/api/lab/options');
    const a3 = options.cases.find((candidate: { key: string }) => candidate.key === 'A3');
    await page.getByRole('button', { name: m['e1.predict.sendWithout'] ?? '' }).click();
    await page.waitForURL(/\/try\/attacker\/run/);
    await page.getByRole('link', { name: m['e1.next.result'] ?? '' }).waitFor({ timeout: RUN_TIMEOUT });

    // Five approaches: five rows; a row opens the settings the running demo publishes.
    await page.goto(`/intro/approaches?lng=${language}`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['approaches.title'] ?? '');
    await expect(page.locator('main ol button')).toHaveCount(5);
    const settings = await api(page, '/api/settings');
    expect(settings, 'the portal publishes the settings').not.toBeNull();
    const rows = page.getByRole('list', { name: m['approaches.title'] ?? '' });
    await rows.getByRole('button', { name: new RegExp(`^${escape(m['control.C1.name'] ?? '')}`) }).click();
    const dialog = page.getByRole('dialog');
    if (settings.threshold.volumeLimit !== null) {
      await expect(dialog).toContainText(
        format(m['settings.items'] ?? '', { n: items(settings.threshold.volumeLimit, language) }),
      );
    }
    expect(await seriousViolations(page)).toEqual([]);
    await page.keyboard.press('Escape');
    await rows.getByRole('button', { name: new RegExp(`^${escape(m['control.D.name'] ?? '')}`) }).click();
    await expect(dialog).toContainText(
      format(m['settings.D.inspectorValue'] ?? '', { n: settings.engine.inspectorConditions }),
    );
    await page.keyboard.press('Escape');

    // Where they sit: the door outside, five steps inside, and this demo's own code.
    await page.goto(`/intro/approaches/where?lng=${language}`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['where.title'] ?? '');
    await expect(page.locator('main figure ol li')).toHaveCount(5);
    await page.getByRole('button', { name: m['where.code'] ?? '' }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');
    expect(await seriousViolations(page)).toEqual([]);

    // The dilemma: every figure is the benchmark's count; the band only while its fact holds.
    await page.goto(`/try/summary/dilemma?lng=${language}`);
    const benchmark = await api(page, '/api/benchmark');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(
      format(m['dilemma.title'] ?? '', { cases: items(benchmark.scope.cases, language) }),
    );
    const control = (id: string): Score =>
      benchmark.controls.find((entry: Score) => entry.control === id) as Score;
    await expect(page.locator('section[aria-labelledby="dilemma-C1"] dd').nth(0)).toHaveText(
      items(control('C1').falseBlock.hits, language),
    );
    await expect(page.locator('section[aria-labelledby="dilemma-C1"] dd').nth(1)).toHaveText(
      items(control('C1').missed, language),
    );
    await expect(page.locator('section[aria-labelledby="dilemma-C2"] dd').nth(0)).toHaveText(
      items(control('C2').stopped.hits, language),
    );
    await expect(page.locator('section[aria-labelledby="dilemma-D"] dd').nth(0)).toHaveText(
      items(control('D').falseBlock.hits, language),
    );
    await expect(page.locator('section[aria-labelledby="dilemma-D"] dd').nth(1)).toHaveText(
      items(benchmark.riskJudged.stopped, language),
    );
    const bandHolds =
      control('D').falseBlock.hits === 0 &&
      benchmark.riskJudged.runs > 0 &&
      benchmark.riskJudged.stopped === benchmark.riskJudged.runs;
    await expect(page.locator('main')).toContainText(
      bandHolds
        ? (m['dilemma.conclusion'] ?? '')
        : format(m['dilemma.conclusionFallback'] ?? '', {
            blocked: items(control('D').falseBlock.hits, language),
            judged: items(benchmark.riskJudged.runs, language),
            stopped: items(benchmark.riskJudged.stopped, language),
          }),
    );
    expect(await seriousViolations(page)).toEqual([]);

    // What you did: one row per finished run of the visitor, as the server recorded it.
    await page.goto(`/try/summary/recap?lng=${language}`);
    const journey = await api(page, '/api/journey');
    const runs = journey.runs.filter((line: { status: string }) => line.status === 'COMPLETED');
    expect(runs.length).toBeGreaterThan(0);
    await expect(page.locator('main table tbody tr')).toHaveCount(runs.length);
    const own = runs.find((line: { scenarioKey: string }) => line.scenarioKey === 'A3');
    const row = page.locator('main table tbody tr').filter({
      hasText: format(m['recap.did.A3'] ?? '', { items: items(a3.requests[0].items, language) }),
    });
    await expect(row).toContainText(
      format(m['recap.engine'] ?? '', {
        result: m[`recap.result.${own.business.D}`] ?? '',
        items: items(own.exposedItems, language),
      }),
    );
    // S9-05: the row opens the run's decision details over the recap and closes back to it.
    const recapAddress = page.url();
    await row.getByRole('button', { name: m['recap.open'] ?? '' }).click();
    await expect(page).toHaveURL(new RegExp(`detailRun=${own.runId}&detailStep=1`));
    await expect(page.getByRole('dialog').getByRole('tab')).toHaveCount(6);
    await page
      .getByRole('dialog')
      .getByRole('button', { name: m['modal.close'] ?? '' })
      .click();
    await expect(page.getByRole('dialog')).toBeHidden();
    expect(page.url()).toBe(recapAddress);
    await expect(page.locator('main')).toContainText(m['identity.definition'] ?? '');
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);

    // The understanding check: one question at a time, scored by the server; a wrong one leads back to its screen.
    await page.goto(`/try/summary/quiz?lng=${language}`);
    await page.getByLabel(m['quiz.Q1.option.USUAL_AND_COMPANY'] ?? '', { exact: true }).check();
    await page.getByRole('button', { name: m['quiz.nextQuestion'] ?? '' }).click();
    await page.getByLabel(m['quiz.Q2.option.PASSWORD'] ?? '', { exact: true }).check();
    await page.getByRole('button', { name: m['quiz.nextQuestion'] ?? '' }).click();
    await page.getByLabel(m['quiz.Q3.option.SYNC'] ?? '', { exact: true }).check();
    expect(await seriousViolations(page)).toEqual([]);
    await page.getByRole('button', { name: m['quiz.score'] ?? '' }).click();
    await expect(page.getByRole('heading', { level: 2 })).toContainText(
      format(m['quiz.result'] ?? '', { right: 2, total: 3 }),
    );
    await expect(
      page.getByRole('link', {
        name: new RegExp(escape(format(m['quiz.revisit'] ?? '', { difference: m['difference.3'] ?? '' }))),
      }),
    ).toHaveAttribute('href', '/try/owner/result');
    expect(await seriousViolations(page)).toEqual([]);

    // The core value: six cards; the measured lines are the teaser records'.
    await page.goto(`/try/summary/value?lng=${language}`);
    await expect(page.getByRole('list', { name: m['value.title'] ?? '' }).getByRole('listitem')).toHaveCount(
      6,
    );
    const teasers = (await api(page, '/api/teasers')).teasers as TeaserItem[];
    const teaser = (key: string) => teasers.find((entry) => entry.key === key) as TeaserItem;
    const falseBlocks = teaser('LEARN_AFTER_FALSE_BLOCKS').values;
    await expect(page.locator('main')).toContainText(
      format(m['value.measure.3'] ?? '', {
        contexa: items(falseBlocks['contexa'] as number, language),
        numberRule: items(falseBlocks['numberRule'] as number, language),
        normal: items(falseBlocks['normalRuns'] as number, language),
      }),
    );
    const judged = teaser('RISK_JUDGED_STOPPED');
    const judgedValues = {
      judged: items(judged.values['judged'] as number, language),
      stopped: items(judged.values['stopped'] as number, language),
      missed: items(judged.values['judgedAllowMissed'] as number, language),
    };
    await expect(page.locator('main')).toContainText(
      format(m[judged.holds ? 'value.conclusion' : 'value.conclusionFallback'] ?? '', judgedValues),
    );
    expect(await seriousViolations(page)).toEqual([]);

    // What changes with adoption: the measured time, and the default route's end leads to the install steps.
    await page.goto(`/try/summary/adopt?lng=${language}`);
    await expect(page.locator(`main dl[aria-label="${m['adoptChange.title'] ?? ''}"] > div`)).toHaveCount(8);
    await expect(page.locator('main')).toContainText(
      format(m['adoptChange.value.time'] ?? '', {
        p50: seconds(benchmark.engine.analysisP50Ms),
        p95: seconds(benchmark.engine.analysisP95Ms),
      }),
    );
    await expect(page.getByRole('link', { name: m['adoptChange.main'] ?? '' })).toHaveAttribute(
      'href',
      '/adopt',
    );
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
  });
}
