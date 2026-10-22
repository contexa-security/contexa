import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Locator, type Page } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The benchmark on a real portal (R7-검수, RO-3 and RO-10), in Korean and English: five views walked in one order by
 * the bottom bar's main button (summary → situations → judgment and timing → the text sent to the AI → limits, then
 * out to the lab), each "back" leading to the view before, and three windows with their own addresses (how the record
 * was made, the scores by method, a situation). Every value on screen is compared with the portal's own answer
 * (/api/benchmark, /api/benchmark/prompt-quality, /api/cases, the raw downloads); the screens count nothing.
 */
const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
/** A measurement setting to check in place of the latest one (while a newer measurement is still running). */
const BENCH_SETTING = process.env.SHOWCASE_BENCH_SETTING ?? null;
/** The benchmark API of that setting, and the address part the views add for it. */
const BENCHMARK_API = `/api/benchmark${BENCH_SETTING ? `?setting=${BENCH_SETTING}` : ''}`;
const SETTING_PARAM = BENCH_SETTING ? `&setting=${BENCH_SETTING}` : '';
const SETTING_SEARCH = BENCH_SETTING ? `?setting=${BENCH_SETTING}` : '';
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
  readonly rate: number | null;
  readonly low: number | null;
  readonly high: number | null;
  readonly preliminary: boolean;
}

interface Score {
  readonly control: string;
  readonly stopped: Rate;
  readonly stoppedAny: Rate;
  readonly notBlocked: Rate;
  readonly falseBlock: Rate;
  readonly missed: number;
  readonly partlyStopped: number;
  readonly attackUnresolved: number;
  readonly normalUnresolved: number;
  readonly exposedItems: number;
}

interface Pick {
  readonly controls: readonly string[];
  readonly hits: number;
  readonly total: number;
}

type Question = 'mostStopped' | 'mostFalseBlock' | 'cleanMostStopped';
type Group = 'THREAT' | 'NORMAL' | 'UNCERTAIN';

interface CaseRow {
  readonly key: string;
  readonly classification: string;
  readonly title: Record<string, string>;
  readonly runs: number;
  readonly runIds: readonly string[];
  readonly cells: Record<string, { readonly right: number; readonly counted: number }>;
  readonly runResults?: Record<string, Record<string, string>>;
  readonly contexaWrong: boolean;
}

interface Spec {
  readonly settingHash: string;
  readonly firstRunAt: string;
  readonly lastRunAt: string;
}

/** A case's runs all four existing controls let through, with Contexa's results (4.8 of the v21 plan). */
interface BlindSpotCase {
  readonly key: string;
  readonly runs: number;
  readonly allPassed: number;
  readonly passedRuns?: readonly { readonly runId: string; readonly result: string }[];
}

interface View {
  readonly blindSpot?: {
    readonly attacks: readonly BlindSpotCase[];
    readonly normals: readonly BlindSpotCase[];
    readonly totals?: {
      readonly attackRuns: number;
      readonly attackAllPassed: number;
      readonly contexaStopped: number;
      readonly contexaFullyStopped: number;
      readonly normalRuns: number;
      readonly normalAllPassed: number;
      readonly contexaPassed: number;
    };
  };
  readonly spec: Spec;
  readonly specs: readonly Spec[];
  readonly scope: {
    readonly cases: number;
    readonly runs: number;
    readonly attackRuns: number;
    readonly protocols: readonly { readonly repeat: number }[];
  };
  readonly controls: readonly Score[];
  readonly conclusions: Record<Question, Pick>;
  readonly suites: readonly {
    readonly suite: string;
    readonly controls: readonly Score[];
    readonly conclusions: Record<Question, Pick>;
  }[];
  readonly cases: readonly CaseRow[];
  readonly caseCounts: Record<Group, number>;
  readonly contexaWrongCases: Record<Group, number>;
  readonly missedEveryRunCases: readonly string[];
  readonly judgmentTiming: Record<string, number>;
  readonly riskJudged: { readonly runs: number; readonly stopped: number };
  readonly unresolvedRuns: number;
  readonly engine: {
    readonly decisions: number;
    readonly analysisP50Ms: number | null;
    readonly costPerDecisionUsd: number | null;
    readonly reasoning?: {
      readonly mostLikely: Record<string, Record<string, number>>;
      readonly retried: number;
      readonly topRetryReasons: readonly { readonly reason: string; readonly decisions: number }[];
    };
  } | null;
}

interface PromptQuality {
  readonly measuredAt: string;
  readonly delivery: Rate;
  readonly reaction: { readonly direction: Rate };
  readonly invariance: { readonly firstStepFacts: Rate; readonly decisionChanges: number };
  readonly injection: { readonly changed: number; readonly unchanged: Rate };
  readonly accuracy: Rate;
  readonly reasonMatch: Rate;
  readonly consistency: Rate;
  readonly comparison?: {
    readonly baselineBundle: string | null;
    readonly bundle: string | null;
    readonly attackBefore: Rate | null;
    readonly attackNow: Rate | null;
    readonly normalBefore: Rate | null;
    readonly normalNow: Rate | null;
  } | null;
}

const CONTROLS = ['A', 'B', 'C1', 'C2', 'D'];
const QUESTIONS: readonly Question[] = ['mostStopped', 'mostFalseBlock', 'cleanMostStopped'];
const SCORES = ['stopped', 'stoppedAny', 'notBlocked'] as const;
/** The explanations in B-5's bar order (H1 to H5, several, none). */
const EXPLANATIONS = ['H1', 'H2', 'H3', 'H4', 'H5', 'SEVERAL', 'NONE'];

const fraction = (rate: Pick | Rate) => `${rate.hits}/${rate.total}`;

/** The screens' one way to write numbers (src/journey/format.ts, benchPlace.ts); they only format the server's values. */
function percent(value: number | null): string {
  return value === null ? '-' : `${Math.round(value * 1000) / 10}%`;
}

function seconds(ms: number): string {
  return ms >= 1000 ? (ms / 1000).toFixed(1) : (ms / 1000).toFixed(2);
}

function dollars(value: number): string {
  return value >= 0.01 ? value.toFixed(2) : String(Number(value.toPrecision(1)));
}

function count(value: number, language: 'ko' | 'en'): string {
  return value.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US');
}

function utcTime(iso: string): string {
  return iso.replace('T', ' ').replace(/(\.\d+)?Z$/, '');
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

async function overflow(page: Page) {
  return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
}

async function get<T>(page: Page, path: string): Promise<T> {
  const response = await page.request.get(path);
  expect(response.status(), path).toBe(200);
  return (await response.json()) as T;
}

async function shoot(page: Page, name: string, project: string) {
  if (evidenceDir) {
    await page.screenshot({ path: join(evidenceDir, `${name}-${project}.png`), fullPage: true });
  }
}

/** The bottom bar's one main button. */
function mainButton(page: Page): Locator {
  return page.locator('[data-zone="actions"] [data-main]');
}

for (const language of ['ko', 'en'] as const) {
  const words = dictionaries[language];
  const text = (key: string) => required(words[key], `text ${key}`);
  const name = (control: string) => `${text(`control.${control}.name`)}${control === 'C2' ? ' *' : ''}`;
  const caseName = (row: CaseRow) => words[`bench.r7.caseName.${row.key}`] ?? row.title[language] ?? row.key;
  const repeatOf = (view: View) => view.scope.protocols.map((protocol) => protocol.repeat).join(', ') || '-';

  /** The place line names the benchmark and the view; the bottom bar's "back" leads to the view before. */
  async function place(page: Page, view: string, back: string | null) {
    await expect(page.locator('[data-zone="top"]')).toContainText(
      `${text('frame.space.benchmark')} · ${text(`bench.r7.view.${view}`)}`,
    );
    const backLink = page.locator('[data-zone="actions"] a:not([data-main])');
    if (back === null) {
      await expect(backLink).toHaveCount(0);
    } else {
      await expect(backLink).toHaveAttribute('href', `${back}${SETTING_SEARCH}`);
      await expect(backLink).toHaveAccessibleName(new RegExp(text('frame.back')));
    }
  }

  /** Presses the main button, checks it asks the next view's question (RC-3) and waits for that view. */
  async function next(page: Page, label: string, path: RegExp) {
    await expect(mainButton(page)).toHaveCount(1);
    await expect(mainButton(page)).toHaveText(label);
    await mainButton(page).click();
    await page.waitForURL(path);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  }

  async function questionsMatch(page: Page, conclusions: Record<Question, Pick>) {
    const list = page.getByRole('list', { name: text('bench.r7.summary.questions') });
    await expect(list.getByRole('listitem')).toHaveCount(QUESTIONS.length);
    for (const question of QUESTIONS) {
      const pick = conclusions[question];
      const card = list.locator(`li[data-question="${question}"]`);
      await expect(card).toContainText(text(`benchmark.question.${question}`));
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
    // The footnote of the mark only where a marked method is named.
    const marked = QUESTIONS.some((question) => conclusions[question].controls.includes('C2'));
    await expect(page.locator('[data-zone="body"]').getByText(text('bench.r7.footnote'))).toHaveCount(
      marked ? 1 : 0,
    );
  }

  test(`the summary and its two windows show the portal's count (${language})`, async ({ page }, info) => {
    const counted = await get<View>(page, BENCHMARK_API);
    await page.goto(`/benchmark?lng=${language}${SETTING_PARAM}`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(text('bench.chart.summary.title'));
    await place(page, 'summary', null);
    const body = page.locator('[data-zone="body"]');
    await expect(body).toContainText(
      fill(text('bench.r7.summary.scope'), {
        cases: counted.scope.cases,
        attacks: counted.caseCounts.THREAT,
        normals: counted.caseCounts.NORMAL,
        open: counted.caseCounts.UNCERTAIN,
        repeat: repeatOf(counted),
        runs: counted.scope.runs,
      }),
    );
    // B-1 of docs/showcase/벤치마크-구현계획.md: the five criteria with the portal's totals, then each designed pair, a
    // cell per run every existing approach let through with Contexa's result in it, misses included.
    const proof = required(counted.blindSpot, 'the blind-spot proof');
    const totals = required(proof.totals, 'the proof totals');
    const lines = body.getByRole('list', { name: text('bench.chart.proof.title') });
    await expect(lines.locator('[data-proof="g1"]')).toContainText(
      fill(text('bench.chart.proof.ofRuns'), { n: totals.attackAllPassed, of: totals.attackRuns }),
    );
    await expect(lines.locator('[data-proof="g3"]')).toContainText(
      fill(text('bench.chart.proof.g3Value'), {
        stopped: totals.contexaStopped,
        fully: totals.contexaFullyStopped,
        attacks: totals.attackAllPassed,
        passed: totals.contexaPassed,
        normals: totals.normalAllPassed,
      }),
    );
    for (const row of [...proof.attacks, ...proof.normals]) {
      const line = body.locator(`[data-chart="pairs"] [data-case="${row.key}"]`).first();
      if ((await line.count()) === 0) {
        continue;
      }
      await expect(line.locator('[data-run]')).toHaveCount(row.passedRuns?.length ?? 0);
      for (const run of row.passedRuns ?? []) {
        await expect(line.locator(`[data-run="${run.runId}"]`)).toHaveAttribute('data-result', run.result);
      }
      await expect(line).toContainText(
        fill(text('bench.r7.proof.allPassedValue'), { passed: row.allPassed, runs: row.runs }),
      );
    }
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    await shoot(page, `bench-summary-${language}`, info.project.name);

    // The scores by method ("see details"): one table of every method's three scores, then one method in detail.
    const detailChip = body.getByRole('button', { name: text('frame.detail') });
    await detailChip.click();
    await expect(page).toHaveURL(/modal=approach&control=D/);
    const scores = page.getByRole('dialog', { name: text('bench.r7.scores.title') });
    await expect(scores).toBeVisible();
    const rows = scores.locator('table tbody tr');
    await expect(rows).toHaveCount(CONTROLS.length);
    for (const [index, control] of CONTROLS.entries()) {
      const score = required(
        counted.controls.find((candidate) => candidate.control === control),
        control,
      );
      await expect(rows.nth(index).locator('th')).toHaveText(name(control));
      await expect(rows.nth(index).locator('td > span > span:first-child')).toHaveText(
        SCORES.map((scoreName) => fraction(score[scoreName])),
      );
    }
    const chooser = scores.getByLabel(text('bench.r7.scores.choose'));
    for (const control of ['D', 'C1']) {
      const score = required(
        counted.controls.find((candidate) => candidate.control === control),
        control,
      );
      if (control !== 'D') {
        await chooser.selectOption(control);
        await expect(page).toHaveURL(new RegExp(`control=${control}`));
      }
      await expect(chooser).toHaveValue(control);
      const cards = scores.locator('dl > div');
      for (const [index, scoreName] of SCORES.entries()) {
        await expect(cards.nth(index).locator('dt')).toHaveText(text(`bench.r7.score.${scoreName}`));
        await expect(cards.nth(index).locator('dd').first()).toHaveText(fraction(score[scoreName]));
      }
      await expect(scores).toContainText(fill(text('bench.r7.scores.missed'), { n: score.missed }));
      await expect(scores).toContainText(fill(text('bench.r7.scores.partly'), { n: score.partlyStopped }));
      await expect(scores).toContainText(
        fill(text('bench.r7.scores.falseBlock'), { n: score.falseBlock.hits }),
      );
      await expect(scores).toContainText(
        fill(text('bench.r7.scores.unresolved'), {
          attack: score.attackUnresolved,
          normal: score.normalUnresolved,
        }),
      );
    }
    await expect(scores).toContainText(text('settings.note'));
    expect(await seriousViolations(page)).toEqual([]);
    await shoot(page, `bench-scores-${language}`, info.project.name);
    await page.keyboard.press('Escape');
    await expect(scores).toBeHidden();
    await expect(page).not.toHaveURL(/modal=/);
    await expect(detailChip).toBeFocused();

    // How the record was made (the source line): the range sent, the formulas, what one judgment costs, the download.
    const sourceOpen = page
      .locator('[data-zone="source"]')
      .getByRole('button', { name: text('frame.source.open') });
    await expect(page.locator('[data-zone="source"]')).toContainText(text('frame.source.measured'));
    await sourceOpen.click();
    await expect(page).toHaveURL(/modal=method/);
    const method = page.getByRole('dialog', { name: text('bench.r7.method.title') });
    await expect(method).toContainText(
      fill(text('bench.r7.method.scope'), {
        from: utcTime(counted.spec.firstRunAt).slice(0, 16),
        to: utcTime(counted.spec.lastRunAt).slice(0, 16),
        cases: counted.scope.cases,
        runs: counted.scope.runs,
        repeat: repeatOf(counted),
        unresolved: counted.unresolvedRuns,
      }),
    );
    for (const item of ['stopped', 'stoppedAny', 'notBlocked']) {
      await expect(method).toContainText(text(`bench.r7.method.formula.${item}`));
    }
    if (counted.engine) {
      await expect(method).toContainText(count(counted.engine.decisions, language));
      if (counted.engine.analysisP50Ms !== null) {
        await expect(method).toContainText(
          fill(text('detail.seconds'), { s: seconds(counted.engine.analysisP50Ms) }),
        );
      }
      if (counted.engine.costPerDecisionUsd !== null) {
        await expect(method).toContainText(`$${dollars(counted.engine.costPerDecisionUsd)}`);
      }
    } else {
      await expect(method).toContainText(text('bench.r7.ops.none'));
    }
    await expect(method).toContainText(counted.spec.settingHash.slice(0, 12));
    expect(await seriousViolations(page)).toEqual([]);
    // The whole record: every counted run of the setting with its score.
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      method.getByRole('link', { name: text('bench.r7.raw') }).click(),
    ]);
    const raw = JSON.parse(readFileSync(await download.path(), 'utf-8')) as {
      settingHash: string;
      runs: readonly unknown[];
    };
    expect(raw.settingHash).toBe(counted.spec.settingHash);
    expect(raw.runs).toHaveLength(counted.scope.runs);
    // Another setting's record, chosen in the window: the address names it and the window counts that setting.
    // Chosen in the window, another setting's record; not on a named setting (the address keeps it there).
    const other = BENCH_SETTING ? undefined : counted.specs[1];
    if (other) {
      const earlier = await get<View>(page, `/api/benchmark?setting=${other.settingHash}`);
      await method.getByLabel(text('bench.r7.method.settingLabel')).selectOption(other.settingHash);
      await expect(page).toHaveURL(new RegExp(`setting=${other.settingHash}`));
      await expect(method).toContainText(
        fill(text('bench.r7.method.scope'), {
          from: utcTime(earlier.spec.firstRunAt).slice(0, 16),
          to: utcTime(earlier.spec.lastRunAt).slice(0, 16),
          cases: earlier.scope.cases,
          runs: earlier.scope.runs,
          repeat: repeatOf(earlier),
          unresolved: earlier.unresolvedRuns,
        }),
      );
      await method.getByLabel(text('bench.r7.method.settingLabel')).selectOption(counted.spec.settingHash);
      await expect(page).not.toHaveURL(/setting=/);
    }
    await page.keyboard.press('Escape');
    await expect(method).toBeHidden();
    await expect(page).not.toHaveURL(/modal=/);

    await next(page, text('bench.r7.next.approaches'), /\/benchmark\/approaches/);
  });

  test(`the approaches on one chart and the three questions (${language})`, async ({ page }, info) => {
    const counted = await get<View>(page, BENCHMARK_API);
    await page.goto(`/benchmark/approaches?lng=${language}${SETTING_PARAM}`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(text('bench.chart.approaches.title'));
    await place(page, 'approaches', '/benchmark');
    const body = page.locator('[data-zone="body"]');
    // B-2: a point per approach, and behind "show as a table" the rates and intervals as the portal sent them.
    // At phone width each approach is a card with the same values; else a point each, the values behind the table.
    const narrow = (page.viewportSize()?.width ?? 1440) <= 640;
    if (narrow) {
      await expect(body.locator('[data-chart="scatter"] li[data-point]')).toHaveCount(CONTROLS.length);
    } else {
      await expect(body.locator('[data-chart="scatter"] svg [data-point]')).toHaveCount(CONTROLS.length);
      await body.getByText(text('bench.chart.table')).click();
    }
    for (const control of CONTROLS) {
      const score = required(
        counted.controls.find((candidate) => candidate.control === control),
        control,
      );
      const row = body.locator(
        narrow
          ? `[data-chart="scatter"] li[data-point="${control}"]`
          : `[data-chart="scatter"] tr[data-row="${control}"]`,
      );
      for (const rate of [score.stoppedAny, score.falseBlock]) {
        await expect(row).toContainText(
          `${fraction(rate)} · ${percent(rate.rate)} (${fill(text('bench.r7.rangeValue'), {
            low: percent(rate.low),
            high: percent(rate.high),
          })}`,
        );
      }
    }
    await questionsMatch(page, counted.conclusions);
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    await shoot(page, `bench-approaches-${language}`, info.project.name);
    // A named group of situations answers the three questions over that group, and the address keeps it.
    const suite = counted.suites[0];
    if (suite) {
      await page.getByLabel(text('bench.r7.summary.suite')).selectOption(suite.suite);
      await expect(page).toHaveURL(new RegExp(`suite=${suite.suite}`));
      await questionsMatch(page, suite.conclusions);
      await page.getByLabel(text('bench.r7.summary.suite')).selectOption('');
      await expect(page).not.toHaveURL(/suite=/);
      await questionsMatch(page, counted.conclusions);
    }
    await next(page, text('bench.r7.next.cases'), /\/benchmark\/cases/);
  });

  test(`the situation list, its pages and a situation's window (${language})`, async ({ page }, info) => {
    const counted = await get<View>(page, BENCHMARK_API);
    const catalog = await get<{
      cases: readonly { key: string; rationale: Record<string, string> }[];
    }>(page, '/api/cases');
    await page.goto(`/benchmark/cases?lng=${language}${SETTING_PARAM}`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(text('bench.r7.cases.title'));
    await place(page, 'cases', '/benchmark/approaches');
    const body = page.locator('[data-zone="body"]');
    // B-3: every situation on one map (a row, or a card at phone width), a cell per run for each approach, under the
    // server's counts of situations and of the ones Contexa got wrong.
    await expect(body).toContainText(
      fill(text('bench.chart.map.counts'), {
        attacks: counted.caseCounts.THREAT,
        attacksWrong: counted.contexaWrongCases.THREAT,
        normals: counted.caseCounts.NORMAL,
        normalsWrong: counted.contexaWrongCases.NORMAL,
        open: counted.caseCounts.UNCERTAIN,
      }),
    );
    const map = body.locator('[data-chart="map"]');
    // Every group open (the first one is open on arrival; a group's title folds it).
    const closed = map.locator('details:not([open]) > summary');
    while ((await closed.count()) > 0) {
      await closed.first().click();
    }
    for (const row of counted.cases) {
      const line = map.locator(`[data-case="${row.key}"]`);
      await expect(line).toHaveCount(1);
      await expect(line.getByRole('button', { name: caseName(row) })).toBeVisible();
      await expect(line.locator('[data-run]')).toHaveCount(
        Object.keys(row.runResults ?? {}).length * CONTROLS.length,
      );
    }
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    await shoot(page, `bench-cases-${language}`, info.project.name);
    // The filter keeps the situations the server flagged as handled wrong by Contexa.
    await body.getByLabel(text('bench.chart.map.wrongOnly')).check();
    await expect(map.locator('[data-case]')).toHaveCount(
      counted.cases.filter((row) => row.contexaWrong).length,
    );
    await body.getByLabel(text('bench.chart.map.wrongOnly')).uncheck();

    // A situation's window ("see details" at the server's first one): what handling it right means, why, every
    // method's right/counted and the requests sent in it, as stored.
    const normal = required(counted.cases[0], 'the first situation');
    const detailChip = page
      .locator('[data-zone="body"]')
      .getByRole('button', { name: text('bench.r7.cases.detail') });
    await detailChip.click();
    await expect(page).toHaveURL(new RegExp(`modal=case&case=${normal.key}`));
    const situation = (row: CaseRow) =>
      page.getByRole('dialog', { name: fill(text('bench.r7.case.windowTitle'), { name: caseName(row) }) });
    async function windowMatches(row: CaseRow) {
      const dialog = situation(row);
      await expect(dialog).toBeVisible();
      const answer =
        row.classification === 'THREAT' ? 'stop' : row.classification === 'NORMAL' ? 'pass' : 'none';
      await expect(dialog).toContainText(text(`bench.r7.case.answer.${answer}`));
      const rationale = catalog.cases.find((entry) => entry.key === row.key)?.rationale[language];
      if (rationale) {
        await expect(dialog).toContainText(rationale);
      }
      const cells = dialog.locator('dl > div');
      await expect(cells.locator('dt')).toHaveText(CONTROLS.map(name));
      await expect(cells.locator('dd')).toHaveText(
        CONTROLS.map((control) => {
          const cell = row.cells[control];
          return cell ? `${cell.right}/${cell.counted}` : text('bench.r7.notCounted');
        }),
      );
      await expect(dialog).toContainText(fill(text('bench.r7.case.runs'), { n: count(row.runs, language) }));
      await expect(dialog.locator('ul li code')).toHaveText([...row.runIds]);
    }
    await windowMatches(normal);
    expect(await seriousViolations(page)).toEqual([]);
    await shoot(page, `bench-case-${language}`, info.project.name);

    // Another situation chosen in place, then one of its requests opens the decision details in the window's place.
    const attack = required(
      counted.cases.find(
        (row) => row.classification === 'THREAT' && row.runIds.length > 0 && row.key !== normal.key,
      ),
      'an attack situation with requests',
    );
    await situation(normal).getByLabel(text('bench.r7.case.choose')).selectOption(attack.key);
    await expect(page).toHaveURL(new RegExp(`modal=case&case=${attack.key}`));
    await windowMatches(attack);
    const run = required(attack.runIds[0], 'a request of the situation');
    await situation(attack).getByRole('button', { name: run }).click();
    await expect(page).toHaveURL(new RegExp(`modal=detail.*detailRun=${run}`));
    await expect(page.getByRole('dialog').getByRole('tab')).toHaveCount(7);
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`modal=case&case=${attack.key}`));
    await expect(situation(attack)).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(situation(attack)).toBeHidden();
    await expect(page).not.toHaveURL(/modal=/);

    // A situation's own address opens the same window over the list.
    await page.goto(`/benchmark/cases/${attack.key}?lng=${language}${SETTING_PARAM}`);
    await expect(page).toHaveURL(new RegExp(`/benchmark/cases\\?.*modal=case&case=${attack.key}`));
    await windowMatches(attack);
    await page.keyboard.press('Escape');
    await expect(situation(attack)).toBeHidden();

    await next(page, text('bench.r7.next.judgment'), /\/benchmark\/judgment/);
  });

  test(`judgment and timing, the trust in the judgment and the limits, out to the lab (${language})`, async ({
    page,
  }, info) => {
    const counted = await get<View>(page, BENCHMARK_API);
    // The setting's own record, as the views ask for it (404 until one is published for the setting).
    const qualityResponse = await page.request.get(
      `/api/benchmark/prompt-quality?setting=${counted.spec.settingHash}`,
    );
    const quality =
      qualityResponse.status() === 404 ? null : ((await qualityResponse.json()) as PromptQuality);
    if (quality === null) {
      expect(qualityResponse.status()).toBe(404);
    }
    const timing = counted.judgmentTiming;

    // Judgment and timing: how each attack Contexa received ended, one bar and the count of each kind.
    await page.goto(`/benchmark/judgment?lng=${language}${SETTING_PARAM}`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(
      fill(text('bench.r7.judgment.title'), { n: counted.scope.attackRuns }),
    );
    await place(page, 'judgment', '/benchmark/cases');
    const kinds = ['STATIC_REFUSAL', 'BEFORE_RESPONSE', 'NEXT_REQUEST', 'JUDGED_ALLOW', 'OTHER'].filter(
      (kind) => kind !== 'OTHER' || (timing[kind] ?? 0) > 0,
    );
    await expect(page.locator('main li[data-kind]')).toHaveCount(kinds.length);
    for (const kind of kinds) {
      const item = page.locator(`main li[data-kind="${kind}"]`);
      await expect(item).toContainText(text(`bench.r7.judgment.kind.${kind}`));
      await expect(item).toContainText(fill(text('benchmark.times'), { n: timing[kind] ?? 0 }));
    }
    await expect(
      page.getByRole('img', { name: text('bench.r7.judgment.barLabel') }).locator('[data-kind]'),
    ).toHaveCount(kinds.filter((kind) => (timing[kind] ?? 0) > 0).length);
    const body = page.locator('[data-zone="body"]');
    await expect(body).toContainText(
      fill(text('bench.r7.judgment.timing'), { n: timing['NEXT_REQUEST'] ?? 0 }),
    );
    await expect(body).toContainText(
      fill(text('bench.r7.judgment.judged'), { n: timing['JUDGED_ALLOW'] ?? 0 }),
    );
    await expect(body).toContainText(
      fill(text('bench.r7.judgment.risk'), {
        runs: counted.riskJudged.runs,
        stopped: counted.riskJudged.stopped,
      }),
    );
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    await shoot(page, `bench-judgment-${language}`, info.project.name);

    // B-5: whether the AI's judgment can be trusted, as the portal counted the model calls of the setting.
    await next(page, text('bench.r7.next.reasoning'), /\/benchmark\/reasoning/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(text('bench.chart.reasoning.title'));
    await place(page, 'reasoning', '/benchmark/judgment');
    const trust = page.locator('[data-zone="body"]');
    const reasoning = counted.engine?.reasoning ?? null;
    if (reasoning === null) {
      await expect(trust).toContainText(text('bench.chart.reasoning.none'));
    } else {
      await trust.getByText(text('bench.chart.table')).click();
      for (const truth of ['THREAT', 'NORMAL']) {
        const counts = reasoning.mostLikely[truth];
        if (!counts) {
          continue;
        }
        await expect(trust.locator(`[data-chart="stack"] tr[data-row="${truth}"] td`)).toHaveText(
          EXPLANATIONS.map((id) => String(counts[id] ?? 0)),
        );
      }
      await expect(trust).toContainText(
        fill(text('bench.chart.reasoning.retried'), { n: count(reasoning.retried, language) }),
      );
      for (const reason of reasoning.topRetryReasons) {
        await expect(trust.locator('code[data-original]').filter({ hasText: reason.reason })).toHaveCount(1);
      }
      // G5 as the views read it: the setting's published decision quality (BM-S8), else its prompt quality.
      const decided = await page.request.get(
        `/api/benchmark/decision-quality?setting=${counted.spec.settingHash}`,
      );
      const reasonRate =
        decided.status() === 200
          ? ((await decided.json()) as { quality: { reasonMatch: Rate } }).quality.reasonMatch
          : (quality?.reasonMatch ?? null);
      if (reasonRate !== null && reasonRate.total > 0) {
        await expect(trust).toContainText(
          fill(text('bench.r7.proof.reasons'), { hits: reasonRate.hits, total: reasonRate.total }),
        );
      }
    }
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    await shoot(page, `bench-reasoning-${language}`, info.project.name);

    // The limits: what Contexa let through in every repeat, its three numbers and why the first is low.
    await next(page, text('bench.r7.next.limits'), /\/benchmark\/limits/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(text('bench.r7.limits.title'));
    await place(page, 'limits', '/benchmark/reasoning');
    const contexa = required(
      counted.controls.find((candidate) => candidate.control === 'D'),
      'Contexa',
    );
    const missed = counted.missedEveryRunCases.map((key) =>
      required(
        counted.cases.find((row) => row.key === key),
        `missed situation ${key}`,
      ),
    );
    const limits = page.locator('[data-zone="body"]');
    await expect(limits).toContainText(
      missed.length > 0
        ? fill(text('bench.r7.limits.missed'), { repeat: repeatOf(counted), n: missed.length })
        : fill(text('bench.r7.limits.missedNone'), { repeat: repeatOf(counted) }),
    );
    // B-6: the attacks Contexa let through and the normal work it blocked at least once, as the server flagged them.
    for (const [kind, title] of [
      ['THREAT', 'bench.chart.limits.missedTitle'],
      ['NORMAL', 'bench.chart.limits.haltedTitle'],
    ] as const) {
      const group = limits.getByRole('region', { name: text(title) });
      const wrong = counted.cases.filter((row) => row.classification === kind && row.contexaWrong);
      await expect(group.locator('[data-case]')).toHaveCount(wrong.length);
      for (const row of wrong) {
        await expect(group.locator(`[data-case="${row.key}"]`)).toContainText(caseName(row));
      }
    }
    await expect(limits.getByRole('button', { name: text('frame.detail') })).toHaveCount(
      missed.length > 0 ? 1 : 0,
    );
    await expect(limits.locator('dl > div > dt')).toHaveText([
      text('bench.r7.score.stopped'),
      text('bench.r7.score.stoppedAny'),
      text('bench.r7.limits.exposed'),
    ]);
    await expect(limits.locator('dl > div > dd')).toHaveText([
      fraction(contexa.stopped),
      fraction(contexa.stoppedAny),
      fill(text('bench.r7.items'), { items: count(contexa.exposedItems, language) }),
    ]);
    await expect(limits).toContainText(
      fill(text('bench.r7.limits.why'), {
        timing: timing['NEXT_REQUEST'] ?? 0,
        judged: timing['JUDGED_ALLOW'] ?? 0,
      }),
    );
    await expect(limits.getByRole('heading', { name: text('bench.r7.limits.explainTitle') })).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    await shoot(page, `bench-limits-${language}`, info.project.name);

    // The last view's main button leads out of the benchmark, to the lab.
    await expect(mainButton(page)).toHaveAttribute('href', '/lab');
    await next(page, text('bench.r7.next.lab'), /\/lab(\?|$)/);
  });
}
