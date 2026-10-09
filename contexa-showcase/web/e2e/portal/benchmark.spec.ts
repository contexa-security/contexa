import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * S10, the benchmark (7.8) on a real portal, in Korean and English: the summary's range, its three questions and its
 * table as /api/benchmark counted them, the approach card and the measurement method windows, the raw data download,
 * the case list's tabs, filter and pages, the case window opening the decision details in its place and coming back,
 * the judgment-and-timing bar and the limits. The screens count nothing; every value is compared with the API.
 */
const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

type Dictionary = Record<string, string>;
const dictionaries: Record<'ko' | 'en', Dictionary> = {
  ko: JSON.parse(readFileSync(new URL('../../src/i18n/ko.json', import.meta.url), 'utf-8')) as Dictionary,
  en: JSON.parse(readFileSync(new URL('../../src/i18n/en.json', import.meta.url), 'utf-8')) as Dictionary,
};

function required<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) {
    throw new Error(`missing: ${what}`);
  }
  return value;
}

function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => String(values[key] ?? `{{${key}}}`));
}

interface Rate {
  readonly hits: number;
  readonly total: number;
}

interface Score {
  readonly control: string;
  readonly stopped: Rate;
  readonly stoppedAny: Rate;
  readonly notBlocked: Rate;
  readonly missed: number;
  readonly partlyStopped: number;
}

interface Pick {
  readonly controls: readonly string[];
  readonly hits: number;
  readonly total: number;
}

interface View {
  readonly spec: { readonly settingHash: string };
  readonly scope: { readonly cases: number; readonly runs: number; readonly attackRuns: number };
  readonly controls: readonly Score[];
  readonly conclusions: Record<'mostStopped' | 'mostFalseBlock' | 'cleanMostStopped', Pick>;
  readonly suites: readonly { readonly suite: string; readonly controls: readonly Score[] }[];
  readonly cases: readonly {
    readonly key: string;
    readonly classification: string;
    readonly runIds: readonly string[];
    readonly contexaWrong: boolean;
    readonly cells: Record<string, { readonly right: number; readonly counted: number }>;
  }[];
  readonly caseCounts: Record<string, number>;
  readonly contexaWrongCases: Record<string, number>;
  readonly missedEveryRunCases: readonly string[];
  readonly judgmentTiming: Record<string, number>;
  readonly engine: { readonly decisions: number } | null;
}

const CONTROLS = ['A', 'B', 'C1', 'C2', 'D'];
const fraction = (rate: Rate) => `${rate.hits}/${rate.total}`;

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

async function overflow(page: Page) {
  return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
}

async function view(page: Page): Promise<View> {
  return (await (await page.request.get('/api/benchmark')).json()) as View;
}

for (const language of ['ko', 'en'] as const) {
  const text = (key: string) => required(dictionaries[language][key], `text ${key}`);
  const name = (control: string) => `${text(`control.${control}.name`)}${control === 'C2' ? ' *' : ''}`;

  test(`the summary shows the portal's count and opens its windows (${language})`, async ({ page }, info) => {
    const counted = await view(page);
    await page.goto(`/benchmark?lng=${language}`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(text('benchmark.summary.title'));
    // Only the benchmark's own menu item is lit, though the concept path lists the benchmark as its last step.
    await expect(page.locator("header nav a[class*='navActive']")).toHaveText([text('nav.benchmark')]);
    const main = page.locator('main');

    // The three questions, answered by the approaches the server named.
    for (const question of ['mostStopped', 'mostFalseBlock', 'cleanMostStopped'] as const) {
      const pick = counted.conclusions[question];
      const card = main.locator('li').filter({ hasText: text(`benchmark.question.${question}`) });
      await expect(card).toContainText(
        pick.controls.length > 0
          ? pick.controls.map(name).join(' · ')
          : text(`benchmark.answerNone.${question}`),
      );
      if (pick.controls.length > 0) {
        await expect(card).toContainText(
          fill(text(`benchmark.answerValue.${question}`), { hits: pick.hits, total: pick.total }),
        );
      }
    }

    // The table: every approach's three scores as counted.
    const rows = main.locator('table tbody tr');
    await expect(rows).toHaveCount(CONTROLS.length);
    for (const [index, control] of CONTROLS.entries()) {
      const score = required(
        counted.controls.find((candidate) => candidate.control === control),
        control,
      );
      await expect(rows.nth(index).locator('td > span > span:first-child')).toHaveText([
        fraction(score.stopped),
        fraction(score.stoppedAny),
        fraction(score.notBlocked),
      ]);
    }
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `bench-summary-${language}-${info.project.name}.png`),
        fullPage: true,
      });
    }

    // The approach card: its scores and wrong answers, the same counts.
    const contexa = required(
      counted.controls.find((candidate) => candidate.control === 'D'),
      'Contexa',
    );
    await rows.nth(4).getByRole('button').click();
    await expect(page).toHaveURL(/modal=approach&control=D/);
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText(fraction(contexa.stoppedAny));
    await expect(dialog).toContainText(fill(text('benchmark.approach.missed'), { n: contexa.missed }));
    await expect(dialog).toContainText(fill(text('benchmark.approach.partly'), { n: contexa.partlyStopped }));
    await expect(dialog).toContainText(text('settings.note'));
    expect(await seriousViolations(page)).toEqual([]);
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(page).not.toHaveURL(/modal=/);

    // How it was measured.
    await page.getByRole('button', { name: text('benchmark.method.open') }).click();
    await expect(page).toHaveURL(/modal=method/);
    await expect(dialog).toContainText(text('benchmark.method.formula.stoppedAny'));
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();

    // The raw data: every counted run of the setting with its score.
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('link', { name: text('benchmark.summary.raw') }).click(),
    ]);
    const raw = JSON.parse(readFileSync(await download.path(), 'utf-8')) as {
      settingHash: string;
      runs: readonly unknown[];
    };
    expect(raw.settingHash).toBe(counted.spec.settingHash);
    expect(raw.runs).toHaveLength(counted.scope.runs);

    // The case group the rules were not written for: the same table over that group.
    const suite = counted.suites[0];
    if (suite) {
      await page.getByRole('button', { name: text(`benchmark.suite.${suite.suite}`) }).click();
      await expect(page).toHaveURL(new RegExp(`suite=${suite.suite}`));
      const suiteContexa = required(
        suite.controls.find((candidate) => candidate.control === 'D'),
        'Contexa in the group',
      );
      await expect(rows.nth(4).locator('td > span > span:first-child').nth(1)).toHaveText(
        fraction(suiteContexa.stoppedAny),
      );
    }
  });

  test(`the case list, its filter and pages, and a case window over it (${language})`, async ({
    page,
  }, info) => {
    const counted = await view(page);
    await page.goto(`/benchmark/cases?lng=${language}`);
    const tabs = page.getByRole('tablist', { name: text('benchmark.cases.tabs') });
    await expect(tabs.getByRole('tab').first()).toHaveText(
      fill(text('benchmark.cases.tab.attack'), { n: counted.caseCounts['THREAT'] ?? 0 }),
    );
    const attacks = counted.cases.filter((row) => row.classification === 'THREAT');
    const rows = page.locator('main table tbody tr');
    await expect(rows).toHaveCount(Math.min(10, attacks.length));
    const first = required(attacks[0], 'an attack case');
    await expect(rows.first().locator('td > span')).toHaveText(
      CONTROLS.map((control) => {
        const cell = first.cells[control];
        return cell ? `${cell.right}/${cell.counted}` : '-';
      }),
    );
    if (attacks.length > 10) {
      await page.getByRole('button', { name: text('benchmark.cases.next') }).click();
      await expect(page).toHaveURL(/page=2/);
      await expect(rows).toHaveCount(Math.min(10, attacks.length - 10));
      await page.getByRole('button', { name: text('benchmark.cases.previous') }).click();
    }
    await page
      .getByRole('button', {
        name: fill(text('benchmark.cases.wrong'), { n: counted.contexaWrongCases['THREAT'] ?? 0 }),
      })
      .click();
    const wrong = attacks.filter((row) => row.contexaWrong);
    await expect(rows).toHaveCount(Math.min(10, wrong.length));
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `bench-cases-${language}-${info.project.name}.png`),
        fullPage: true,
      });
    }

    // The case window: its right answer's reason, and a run that opens the decision details in its place.
    const wrongCase = required(wrong[0], 'a case Contexa got wrong');
    const catalog = (await (await page.request.get('/api/cases')).json()) as {
      cases: readonly { key: string; rationale: Record<string, string> }[];
    };
    const rationale = catalog.cases.find((entry) => entry.key === wrongCase.key)?.rationale[language];
    await rows.first().getByRole('button').click();
    await expect(page).toHaveURL(new RegExp(`modal=case&case=${wrongCase.key}`));
    const dialog = page.getByRole('dialog');
    if (rationale) {
      await expect(dialog).toContainText(rationale);
    }
    const run = required(wrongCase.runIds[0], 'a run of the case');
    await dialog.getByRole('button', { name: run }).click();
    await expect(page).toHaveURL(new RegExp(`modal=detail.*detailRun=${run}`));
    await expect(dialog.getByRole('tab')).toHaveCount(6);
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`modal=case&case=${wrongCase.key}`));
    await expect(dialog).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();

    // The case's own address opens the same window over the list; the operations tab counts the decisions.
    await page.goto(`/benchmark/cases/${first.key}?lng=${language}`);
    await expect(page).toHaveURL(new RegExp(`/benchmark/cases\\?.*modal=case&case=${first.key}`));
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');
    await page.getByRole('tab', { name: text('benchmark.cases.tab.ops') }).click();
    if (counted.engine) {
      await expect(page.locator('main')).toContainText(
        counted.engine.decisions.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US'),
      );
    }
  });

  test(`judgment and timing, and the limits (${language})`, async ({ page }, info) => {
    const counted = await view(page);
    await page.goto(`/benchmark/judgment?lng=${language}`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(
      fill(text('benchmark.judgment.title'), { n: counted.scope.attackRuns }),
    );
    for (const kind of ['STATIC_REFUSAL', 'BEFORE_RESPONSE', 'NEXT_REQUEST', 'JUDGED_ALLOW']) {
      await expect(
        page.locator('main li').filter({ hasText: text(`benchmark.judgment.kind.${kind}`) }),
      ).toContainText(fill(text('benchmark.times'), { n: counted.judgmentTiming[kind] ?? 0 }));
    }
    await expect(page.locator('main')).toContainText(
      fill(text('benchmark.judgment.timing'), { n: counted.judgmentTiming['NEXT_REQUEST'] ?? 0 }),
    );
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `bench-judgment-${language}-${info.project.name}.png`),
        fullPage: true,
      });
    }

    await page.getByRole('link', { name: text('benchmark.toLimits') }).click();
    await page.waitForURL(/\/benchmark\/limits/);
    const missed = counted.missedEveryRunCases.length;
    const contexa = required(
      counted.controls.find((candidate) => candidate.control === 'D'),
      'Contexa',
    );
    await expect(page.locator('main ul li h2')).toHaveCount(missed);
    const big = page.locator('main dl dd');
    await expect(big.nth(0)).toHaveText(fraction(contexa.stopped));
    await expect(big.nth(1)).toHaveText(fraction(contexa.stoppedAny));
    await expect(page.locator('main')).toContainText(
      fill(text('benchmark.limits.why'), {
        timing: counted.judgmentTiming['NEXT_REQUEST'] ?? 0,
        judged: counted.judgmentTiming['JUDGED_ALLOW'] ?? 0,
      }),
    );
    await expect(page.getByRole('link', { name: text('benchmark.limits.toLab') })).toHaveAttribute(
      'href',
      '/lab',
    );
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `bench-limits-${language}-${info.project.name}.png`),
        fullPage: true,
      });
    }
  });
}
