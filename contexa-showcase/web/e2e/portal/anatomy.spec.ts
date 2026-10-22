import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * S9, the decision details (anat-1, anat-2, 7.7; redesign R7 RO-1, RO-11) on a real portal, in Korean and English: the
 * window over a screen with its own address, the situation's name in its title, and seven tabs whose every value is the
 * one the visitor API stored for the step (anatomy, step result, score, received comparison, raw texts). The runs are the
 * latest measurement's, picked from /api/benchmark: a step with a model decision and a step refused by an earlier
 * decision. The SHA-256 the window shows equals the hash of the downloaded bytes. The old anatomy address and the
 * window's shared address open the same window.
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

/** A value the stored records must hold; the test fails naming it when they do not. */
function required<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) {
    throw new Error(`missing: ${what}`);
  }
  return value;
}

/** The screens' one way to write seconds and counts (src/journey/format.ts). */
function seconds(ms: number): string {
  return ms >= 1000 ? (ms / 1000).toFixed(1) : (ms / 1000).toFixed(2);
}

function count(value: number, language: 'ko' | 'en'): string {
  return value.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US');
}

function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => String(values[key] ?? `{{${key}}}`));
}

interface Anatomy {
  readonly context: {
    readonly company: {
      readonly approvalRequired: boolean | null;
      readonly approvalMissing: boolean | null;
    } | null;
    readonly rag: { readonly ragAuthorizedDocumentCount: number | null } | null;
  };
  readonly interpretation: {
    readonly recorded: {
      readonly finalAction: string | null;
      readonly reasoningCode: string | null;
      readonly applied: string | null;
    };
    readonly calls: readonly unknown[];
    readonly timings: { readonly totalAnalysisMs: number | null };
    readonly timeline: readonly unknown[];
    readonly sinceStartMs: readonly (number | null)[];
  };
  readonly truth: {
    readonly classification: string | null;
    readonly rationale: { readonly ko: string; readonly en: string } | null;
    readonly verdict: {
      readonly score: { readonly result: string; readonly applied: string | null };
      readonly source: string;
    } | null;
  };
  readonly juxtaposition: {
    readonly sensitivity: string | null;
    readonly companyFacts: readonly string[];
    readonly adverseMet: number;
    readonly adverseChecked: number;
  };
  readonly promptLines: {
    readonly systemPhysical: number;
    readonly userPhysical: number;
    readonly sections: readonly unknown[];
    readonly bundles: readonly { readonly bundle: string; readonly lines: number }[];
  } | null;
  readonly figures: {
    readonly departureCount: number | null;
    readonly baselineBefore: number | null;
    readonly baselineAfter: number | null;
    readonly documentsBefore: number | null;
    readonly documentsAfter: number | null;
    readonly documentsForThisRequest: number;
  };
}

interface Score {
  readonly executedSteps: number;
  readonly scenarioKey: string;
  readonly title: { readonly ko: string; readonly en: string } | null;
}

interface CaseRow {
  readonly key: string;
  readonly runIds: readonly string[];
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

async function firstRun(page: Page, key: string) {
  const benchmark = (await (await page.request.get('/api/benchmark')).json()) as {
    cases: readonly CaseRow[];
  };
  const row = required(
    benchmark.cases.find((candidate) => candidate.key === key),
    `case ${key} in the latest measurement`,
  );
  return required(row.runIds[0], `a run of case ${key}`);
}

async function get<T>(page: Page, path: string): Promise<T> {
  const response = await page.request.get(path);
  expect(response.status(), path).toBe(200);
  return (await response.json()) as T;
}

async function overflow(page: Page) {
  return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
}

for (const language of ['ko', 'en'] as const) {
  const text = (key: string) => required(dictionaries[language][key], `text ${key}`);

  test(`a model decision's seven tabs show what was stored (${language})`, async ({ page }, testInfo) => {
    const runId = await firstRun(page, 'A3');
    const anatomy = await get<Anatomy>(page, `/api/runs/${runId}/steps/1/anatomy`);
    const score = await get<Score>(page, `/api/runs/${runId}/score`);
    const stored = await get<{
      layers: readonly { control: string; evidence: { deliveredItems: number } }[];
    }>(page, `/api/runs/${runId}/steps/1/result`);
    const verdict = required(anatomy.truth.verdict, 'the verdict score');
    const contexa = required(
      stored.layers.find((layer) => layer.control === 'D'),
      "Contexa's stored answer",
    );

    // The window's own address opens it over the first screen, the situation named as stored.
    await page.goto(`/run/${runId}/detail?step=1&lng=${language}`);
    await expect(page).toHaveURL(new RegExp(`[?&]detailRun=${runId}`));
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    // The situation's plain name the lab and the benchmark show (R7-검수 V-45), else the stored title.
    const plainName = dictionaries[language][`bench.r7.caseName.${score.scenarioKey}`];
    await expect(dialog.getByRole('heading', { level: 2 }).first()).toHaveText(
      `${text('detail.r7.title')} ${plainName ?? required(score.title, 'the case title')[language]}`,
    );
    await expect(dialog.getByRole('tab')).toHaveCount(7);

    // Summary (RO-1): each number with its source, the record number on the source line.
    const panel = dialog.getByRole('tabpanel');
    const expected =
      anatomy.truth.classification === 'THREAT'
        ? 'stop'
        : anatomy.truth.classification === 'NORMAL'
          ? 'pass'
          : 'none';
    const applied = verdict.score.applied ?? anatomy.interpretation.recorded.applied;
    if (applied && applied !== 'NONE') {
      await expect(panel).toContainText(text(`detail.r7.applied.${applied}`));
    }
    const total = anatomy.interpretation.timings.totalAnalysisMs;
    if (total !== null) {
      await expect(panel).toContainText(fill(text('detail.r7.seconds'), { s: seconds(total) }));
    }
    await expect(panel).toContainText(
      fill(text('detail.r7.summary.items'), { items: count(contexa.evidence.deliveredItems, language) }),
    );
    if (anatomy.figures.baselineBefore !== null && anatomy.figures.baselineAfter !== null) {
      await expect(panel).toContainText(
        fill(text('detail.r7.summary.learnedValue'), {
          before: count(anatomy.figures.baselineBefore, language),
          after: count(anatomy.figures.baselineAfter, language),
        }),
      );
    }
    await expect(panel).toContainText(text(`detail.r7.expected.${expected}`));
    for (const from of ['decision', 'response', 'learning']) {
      await expect(panel).toContainText(text(`detail.r7.from.${from}`));
    }
    const code = anatomy.interpretation.recorded.reasoningCode;
    await expect(panel).toContainText(
      code ? text(`reason.canonical.${code}`) : text('detail.r7.summary.free'),
    );
    await expect(panel.locator('[data-zone="source"]')).toContainText(runId);
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `detail-summary-${language}-${testInfo.project.name}.png`),
      });
    }

    // The arrow key moves to the next tab, and the tab stays in the address.
    await dialog.getByRole('tab', { name: text('detail.r7.tab.summary') }).focus();
    await page.keyboard.press('ArrowRight');
    await expect(page).toHaveURL(/[?&]detailTab=received/);
    await expect(dialog.getByRole('tab', { name: text('detail.r7.tab.received') })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    await expect(dialog.getByRole('tab', { name: text('detail.r7.tab.received') })).toBeFocused();

    // Received: screen 1-1's comparison, read from this request's record.
    await expect(panel.getByRole('table', { name: text('p1.compare.table') })).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `detail-received-${language}-${testInfo.project.name}.png`),
      });
    }

    // How it judged (RO-11): screen 3-2's nine steps by the same names, with this request's values.
    await dialog.getByRole('tab', { name: text('detail.r7.tab.process') }).click();
    const steps = panel.getByRole('list', { name: text('detail.r7.process.figure') }).getByRole('listitem');
    await expect(steps).toHaveCount(9);
    const names = [
      'request',
      'usual',
      'company',
      'history',
      'prompt',
      'judgement',
      'decision',
      'followUp',
      'learning',
    ];
    for (const [index, id] of names.entries()) {
      await expect(steps.nth(index)).toContainText(text(`p3.how.step.${id}.name`));
    }
    if (anatomy.figures.departureCount !== null) {
      await expect(panel).toContainText(
        fill(text('detail.r7.process.usual'), { n: count(anatomy.figures.departureCount, language) }),
      );
    }
    expect(await seriousViolations(page)).toEqual([]);

    // The text sent to the AI: the inspector's adverse conditions and one part's facts, by one chooser.
    await dialog.getByRole('tab', { name: text('detail.r7.tab.prompt') }).click();
    await expect(panel).toContainText(
      fill(text('detail.r7.prompt.check.adverse'), {
        total: count(anatomy.juxtaposition.adverseChecked, language),
        met: count(anatomy.juxtaposition.adverseMet, language),
      }),
    );
    await expect(panel.getByLabel(text('detail.r7.prompt.choose'))).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);

    // The rules: the four judgments, the overlap rule and the rule lines in plain words.
    await dialog.getByRole('tab', { name: text('detail.r7.tab.rules') }).click();
    await expect(panel).toContainText(text('detail.r7.rules.overlapText'));
    await expect(panel).toContainText(text('detail.r7.rules.lines'));
    expect(await seriousViolations(page)).toEqual([]);

    // The right handling and why, the definition's reason quoted as stored.
    await dialog.getByRole('tab', { name: text('detail.r7.tab.answer') }).click();
    await expect(panel).toContainText(text(`detail.r7.expected.${expected}`));
    if (anatomy.truth.rationale) {
      await expect(panel).toContainText(anatomy.truth.rationale[language]);
    }

    // The original record: the model's own reason first, then the record with the hash of the downloaded file.
    await dialog.getByRole('tab', { name: text('detail.r7.tab.original') }).click();
    await expect(panel.getByLabel(text('detail.r7.original.choose'))).toHaveValue('reason');
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      panel.getByRole('button', { name: text('detail.r7.original.download') }).click(),
    ]);
    const bytes = readFileSync(await download.path());
    const hash = createHash('sha256').update(bytes).digest('hex');
    await expect(panel).toContainText(hash);
    expect(bytes.toString('utf-8').match(/\b[0-9A-F]{32}\b/g) ?? [], 'session identifiers').toEqual([]);
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `detail-original-${language}-${testInfo.project.name}.png`),
      });
    }

    // Esc closes the window and leaves the screen under it, without the window's address.
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(page).not.toHaveURL(/modal=detail/);
  });

  test(`a request refused by an earlier decision says so, and the requests move (${language})`, async ({
    page,
  }) => {
    const runId = await firstRun(page, 'A6');
    const anatomy = await get<Anatomy>(page, `/api/runs/${runId}/steps/2/anatomy`);
    const score = await get<Score>(page, `/api/runs/${runId}/score`);
    const stored = await get<{
      layers: readonly { control: string; httpStatus: number | null; ruleId: string | null }[];
    }>(page, `/api/runs/${runId}/steps/2/result`);
    const contexa = required(
      stored.layers.find((layer) => layer.control === 'D'),
      "Contexa's stored answer",
    );
    const verdict = required(anatomy.truth.verdict, 'the verdict score');
    expect(anatomy.interpretation.recorded.finalAction).toBeNull();

    // The old anatomy address opens the same window at the same request.
    await page.goto(`/runs/${runId}/steps/2?lng=${language}`);
    await expect(page).toHaveURL(/[?&]detailStep=2/);
    const dialog = page.getByRole('dialog');
    const panel = dialog.getByRole('tabpanel');
    await expect(panel).toContainText(text(`detail.r7.notAnalysed.${verdict.source}`));
    await expect(panel).toContainText(`${contexa.httpStatus ?? '-'} · ${contexa.ruleId ?? '-'}`);
    const requests = dialog.getByRole('group', { name: text('detail.r7.requests') });
    await expect(requests).toContainText(
      fill(text('detail.r7.request'), { step: 2, steps: score.executedSteps }),
    );
    await dialog.getByRole('button', { name: text('detail.r7.previous') }).click();
    await expect(page).toHaveURL(/[?&]detailStep=1/);
    await expect(requests).toContainText(
      fill(text('detail.r7.request'), { step: 1, steps: score.executedSteps }),
    );
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    expect(await seriousViolations(page)).toEqual([]);
  });
}

test('an address that is not a run says the record was not found', async ({ page }) => {
  await page.goto('/run/not-a-run/detail?lng=ko');
  await expect(page.getByRole('dialog')).toContainText(
    required(dictionaries.ko['detail.r7.notFound'], 'text'),
  );
});
