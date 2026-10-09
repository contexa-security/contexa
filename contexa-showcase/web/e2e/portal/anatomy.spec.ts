import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * S9, the decision details (anat-1, anat-2, 7.7) on a real portal, in Korean and English: the window over a screen with
 * its own address, the case's name and the request in its title, and six tabs whose every value is the one the
 * visitor API stored for the step (anatomy, step result, score, received comparison, raw texts). The runs are the
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

  test(`a model decision's six tabs show what was stored (${language})`, async ({ page }, testInfo) => {
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

    // The window's own address opens it over the first screen.
    await page.goto(`/run/${runId}/detail?step=1&lng=${language}`);
    await expect(page).toHaveURL(new RegExp(`[?&]detailRun=${runId}`));
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('heading', { level: 2 }).first()).toHaveText(
      fill(text('detail.title'), {
        case: required(score.title, 'the case title')[language],
        step: 1,
        steps: score.executedSteps,
      }),
    );
    await expect(dialog.getByRole('tab')).toHaveCount(6);

    // Summary: right or wrong, the facts that led to the verdict, when it applied, what went out, what was learned.
    const panel = dialog.getByRole('tabpanel');
    await expect(panel).toContainText(text(`anatomy.result.${verdict.score.result}`));
    await expect(panel).toContainText(
      fill(text('e1.reason.differs'), { n: anatomy.figures.departureCount ?? '-' }),
    );
    if (anatomy.juxtaposition.sensitivity) {
      await expect(panel).toContainText(
        fill(text('e1.reason.sensitivity'), {
          level: text(`dim.sensitivity.${anatomy.juxtaposition.sensitivity}`),
        }),
      );
    }
    const applied = verdict.score.applied ?? anatomy.interpretation.recorded.applied;
    if (applied && applied !== 'NONE') {
      await expect(panel).toContainText(text(`timing.applied.${applied}`));
    }
    const total = anatomy.interpretation.timings.totalAnalysisMs;
    if (total !== null) {
      await expect(panel).toContainText(fill(text('detail.seconds'), { s: seconds(total) }));
    }
    await expect(panel).toContainText(
      fill(text('e1.result.items'), { items: count(contexa.evidence.deliveredItems, language) }),
    );
    if (anatomy.figures.baselineBefore !== null && anatomy.figures.baselineAfter !== null) {
      await expect(panel).toContainText(
        fill(text('detail.learnedValue'), {
          before: count(anatomy.figures.baselineBefore, language),
          after: count(anatomy.figures.baselineAfter, language),
        }),
      );
    }
    if (anatomy.figures.documentsBefore !== null && anatomy.figures.documentsAfter !== null) {
      await expect(panel).toContainText(
        fill(text('detail.documents'), {
          before: count(anatomy.figures.documentsBefore, language),
          after: count(anatomy.figures.documentsAfter, language),
          n: count(anatomy.figures.documentsForThisRequest, language),
        }),
      );
    }
    const code = anatomy.interpretation.recorded.reasoningCode;
    await expect(panel).toContainText(code ? text(`reason.canonical.${code}`) : text('e1.reason.free'));
    expect(await seriousViolations(page)).toEqual([]);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `detail-summary-${language}-${testInfo.project.name}.png`),
      });
    }

    // The arrow key moves to the next tab, and the tab stays in the address.
    await dialog.getByRole('tab', { name: text('detail.tab.summary') }).focus();
    await page.keyboard.press('ArrowRight');
    await expect(page).toHaveURL(/[?&]detailTab=received/);
    await expect(dialog.getByRole('tab', { name: text('detail.tab.received') })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    await expect(dialog.getByRole('tab', { name: text('detail.tab.received') })).toBeFocused();

    // Received: the same comparison as before sending, read from this request's record.
    const received = await get<{ departureCount: number; companyAdverseCount: number }>(
      page,
      `/api/runs/${runId}/steps/1/received`,
    );
    await expect(panel.getByRole('heading', { level: 3 }).first()).toHaveText(
      fill(text('e1.compare.differentTitle'), { n: received.departureCount }),
    );
    await expect(panel).toContainText(
      fill(text('detail.received.records'), {
        lines: count(anatomy.juxtaposition.companyFacts.length, language),
        documents:
          anatomy.context.rag?.ragAuthorizedDocumentCount === null ||
          anatomy.context.rag?.ragAuthorizedDocumentCount === undefined
            ? '-'
            : count(anatomy.context.rag.ragAuthorizedDocumentCount, language),
      }),
    );
    expect(await seriousViolations(page)).toEqual([]);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `detail-received-${language}-${testInfo.project.name}.png`),
      });
    }

    // How it decided: every step with the time after the first the server worked out, the calls, the inspector.
    await dialog.getByRole('tab', { name: text('detail.tab.process') }).click();
    await expect(panel.locator('ol').first().locator('li')).toHaveCount(
      anatomy.interpretation.timeline.length,
    );
    await expect(panel.locator('ol').first().locator('li > span:first-child')).toHaveText(
      anatomy.interpretation.sinceStartMs.map((ms) => fill(text('detail.after'), { s: seconds(ms ?? 0) })),
    );
    await expect(panel).toContainText(
      fill(text('detail.process.calls'), { n: anatomy.interpretation.calls.length }),
    );
    await expect(panel).toContainText(
      fill(text('e1.reason.inspector'), {
        total: anatomy.juxtaposition.adverseChecked,
        met: anatomy.juxtaposition.adverseMet,
        names: '',
      }),
    );
    expect(await seriousViolations(page)).toEqual([]);

    // The prompt: the tries' seven bundles of this request.
    await dialog.getByRole('tab', { name: text('detail.tab.prompt') }).click();
    const lines = required(anatomy.promptLines, 'the prompt line counts');
    // The seven named bundles, each with the line count the server counted (OTHER is not one of them).
    const named = lines.bundles.filter((bundle) => bundle.bundle !== 'OTHER');
    const buttons = panel.getByRole('list', { name: text('prompt.bundles') }).getByRole('button');
    await expect(buttons).toHaveCount(named.length);
    for (const bundle of named) {
      await expect(buttons.filter({ hasText: text(`prompt.bundle.${bundle.bundle}`) })).toContainText(
        fill(text('prompt.lines'), { n: count(bundle.lines, language) }),
      );
    }

    // The right answer and why.
    await dialog.getByRole('tab', { name: text('detail.tab.answer') }).click();
    const answer =
      anatomy.truth.classification === 'THREAT'
        ? 'stop'
        : anatomy.truth.classification === 'NORMAL'
          ? 'pass'
          : 'none';
    await expect(panel).toContainText(text(`labCase.answer.${answer}`));
    if (anatomy.truth.rationale) {
      await expect(panel).toContainText(anatomy.truth.rationale[language]);
    }

    // The original: line counts, the folded texts, and the record with the hash of the downloaded file.
    await dialog.getByRole('tab', { name: text('detail.tab.original') }).click();
    await expect(panel).toContainText(
      fill(text('detail.original.lines'), {
        rules: count(lines.systemPhysical, language),
        sections: count(lines.sections.length, language),
        situation: count(lines.userPhysical, language),
      }),
    );
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      panel.getByRole('button', { name: text('source.download') }).click(),
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
    await expect(panel).toContainText(text(`anatomy.notAnalysed.${verdict.source}`));
    await expect(panel).toContainText(`${contexa.httpStatus ?? '-'} · ${contexa.ruleId ?? '-'}`);
    await expect(dialog.getByRole('group', { name: text('detail.requests') })).toContainText(
      fill(text('detail.request'), { step: 2, steps: score.executedSteps }),
    );
    await dialog.getByRole('button', { name: text('detail.previous') }).click();
    await expect(page).toHaveURL(/[?&]detailStep=1/);
    await expect(dialog.getByRole('heading', { level: 2 }).first()).toContainText(`1/${score.executedSteps}`);
    expect(await overflow(page), 'horizontal page scroll').toBeLessThanOrEqual(0);
    expect(await seriousViolations(page)).toEqual([]);
  });
}

test('an address that is not a run says the record was not found', async ({ page }) => {
  await page.goto('/run/not-a-run/detail?lng=ko');
  await expect(page.getByRole('dialog')).toContainText(required(dictionaries.ko['detail.notFound'], 'text'));
});
