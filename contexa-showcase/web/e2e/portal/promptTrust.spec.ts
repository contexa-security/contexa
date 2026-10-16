import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Locator, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

/**
 * The prompt trust checks C-20 to C-23 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 6) on a real portal: the fact
 * cards, source chips and quality ribbon show the facts and quality views of the step (C-20); every reason code leads
 * to the fact card of its fact ID, and a reason without one says "no link" (C-21); the lab result's changed lines are
 * the server's delta of the run (C-22); and every number of the prompt-quality tab has its denominator, the measured
 * date and its 95% interval, or the tab says nothing is measured on a 404 (C-23). Every value on screen is compared
 * with the visitor API's own answer fetched in the test. C-21 and C-22 send real runs (one try 1 run, two lab runs),
 * once, and read the result in both languages.
 */
type Dictionary = Record<string, string>;
const MESSAGES: Record<'ko' | 'en', Dictionary> = {
  ko: JSON.parse(readFileSync(new URL('../../src/i18n/ko.json', import.meta.url), 'utf-8')) as Dictionary,
  en: JSON.parse(readFileSync(new URL('../../src/i18n/en.json', import.meta.url), 'utf-8')) as Dictionary,
};
const LANGUAGES = ['ko', 'en'] as const;
const RUN_TIMEOUT = 240_000;
/** The five parts in reading order and the two folds (web components/facts/factWords.ts). */
const CHUNKS = ['REQUEST', 'SESSION', 'USER_BASELINE', 'DECISION_FACTS', 'UNKNOWN'] as const;
const FOLDS = ['PAST_RECORDS', 'UNTRUSTED_TEXT'] as const;

interface Fact {
  readonly line: number;
  readonly factId: string | null;
  readonly label: string;
  readonly value: string;
  readonly source: string | null;
}

interface Facts {
  readonly available: boolean;
  readonly reason: string | null;
  readonly blocks: readonly { readonly block: string; readonly facts: readonly Fact[] }[];
}

interface Rate {
  readonly hits: number;
  readonly total: number;
  readonly rate: number | null;
  readonly low: number | null;
  readonly high: number | null;
  readonly preliminary: boolean;
}

interface Quality {
  readonly available: boolean;
  readonly bundle: { readonly version: string | null; readonly hash: string | null } | null;
  readonly seal: { readonly packageId: string; readonly packageHash: string | null } | null;
  readonly inspection: {
    readonly verdict: string;
    readonly checks: readonly {
      readonly code: string;
      readonly matched: number;
      readonly mismatched: number;
      readonly unverifiable: number;
    }[];
  } | null;
  readonly reasonCodes: readonly { readonly code: string; readonly fact: string | null }[];
  readonly ribbon: {
    readonly facts: number;
    readonly withSource: number;
    readonly factAccuracy: { readonly matched: number; readonly total: number } | null;
    readonly contradictions: number | null;
    readonly unknown: number;
  } | null;
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

function format(template: string | undefined, values: Readonly<Record<string, string | number>>): string {
  return (template ?? '').replace(/\{\{(\w+)\}\}/g, (_, key: string) => String(values[key] ?? ''));
}

/** A GET of the visitor API from the page, with its status (a 404 is an answer here). */
async function api<T>(page: Page, path: string): Promise<{ readonly status: number; readonly body: T | null }> {
  return page.evaluate(async (target) => {
    const response = await fetch(target, { headers: { Accept: 'application/json' } });
    return { status: response.status, body: response.ok ? await response.json() : null };
  }, path);
}

/** The screens' one way to write a share (web pages/benchmark/benchPlace.ts). */
function percent(value: number | null): string {
  return value === null ? '-' : `${Math.round(value * 1000) / 10}%`;
}

/** The dictionary name of a line's label, a numbered line by its stem (web factWords.ts factKey). */
function labelWords(m: Dictionary, label: string): string {
  const stem = m[`fact.label.${label}`] !== undefined ? label : label.replace(/\d+$/, '');
  return m[`fact.label.${stem}`] ?? m['fact.label.other'] ?? '';
}

function verdictWords(m: Dictionary, action: string | null): string {
  const key =
    { ALLOW: 'verdict.allow', CHALLENGE: 'verdict.verify', ESCALATE: 'verdict.review', BLOCK: 'verdict.block' }[
      action ?? ''
    ] ?? 'verdict.none';
  return m[key] ?? '';
}

/** Reads a view until the server has it (the seal and the inspection come shortly after a decision). */
async function settled<T extends { readonly available: boolean }>(page: Page, path: string): Promise<T | null> {
  let body: T | null = null;
  await expect
    .poll(
      async () => {
        body = (await api<T>(page, path)).body;
        return body?.available ?? false;
      },
      { timeout: 90_000, intervals: [3_000] },
    )
    .toBe(true)
    .catch(() => undefined);
  return body;
}

/** The run the prompt screen shows: the visitor's own try 1 run, or else the measured run the teasers name. */
async function promptRun(page: Page): Promise<string> {
  const journey = (await api<{ runs: { scenarioKey: string; status: string; runId: string }[] }>(page, '/api/journey'))
    .body;
  const own = journey?.runs.find((line) => line.scenarioKey === 'A3' && line.status === 'COMPLETED');
  if (own) {
    return own.runId;
  }
  const teasers = (await api<{ teasers: { key: string; source: { ref: string } | null }[] }>(page, '/api/teasers'))
    .body;
  const ref = teasers?.teasers.find((teaser) => teaser.key === 'G_HOW_LINES')?.source?.ref;
  if (!ref) {
    throw new Error('missing: the measured run of G_HOW_LINES');
  }
  return ref;
}

async function expectRibbon(scope: Locator, m: Dictionary, ribbon: NonNullable<Quality['ribbon']>) {
  const group = scope.getByRole('group', { name: m['quality.ribbon.title'] ?? '' });
  await expect(group).toContainText(format(m['quality.ribbon.source'], { n: ribbon.withSource, total: ribbon.facts }));
  // The inspection's two counts are null until the seal is inspected: the ribbon says it is not inspected yet.
  await expect(group).toContainText(
    ribbon.factAccuracy === null
      ? (m['quality.ribbon.accuracyPending'] ?? '')
      : format(m['quality.ribbon.accuracy'], { n: ribbon.factAccuracy.matched, total: ribbon.factAccuracy.total }),
  );
  await expect(group).toContainText(
    ribbon.contradictions === null
      ? (m['quality.ribbon.contradictionsPending'] ?? '')
      : format(m['quality.ribbon.contradictions'], { n: ribbon.contradictions }),
  );
  await expect(group).toContainText(format(m['quality.ribbon.unknown'], { n: ribbon.unknown }));
  // An item that does not hold is a cross with its counts (the same pair the server gave), never left out.
  const failing = group.locator('li[data-ok="false"]');
  const expected =
    (ribbon.withSource === ribbon.facts ? 0 : 1) +
    (ribbon.factAccuracy === null || ribbon.factAccuracy.matched === ribbon.factAccuracy.total ? 0 : 1) +
    (ribbon.contradictions === null || ribbon.contradictions === 0 ? 0 : 1);
  await expect(failing).toHaveCount(expected);
  await expect(group.locator('li[data-ok="pending"]')).toHaveCount(
    (ribbon.factAccuracy === null ? 1 : 0) + (ribbon.contradictions === null ? 1 : 0),
  );
}

/** A fact card shows the server's fact: its ID, the entry's words, the source chip, and the line as sent. */
async function expectCard(page: Page, m: Dictionary, fact: Fact) {
  const card = page.locator(`[id="fact-line-${fact.line}"]`);
  await expect(card).toBeVisible();
  if (fact.factId) {
    await expect(card).toContainText(fact.factId);
  }
  await expect(card).toContainText(labelWords(m, fact.label));
  await expect(card).toContainText(m[`fact.source.${fact.source ?? 'NONE'}`] ?? '');
  await card.getByRole('button', { name: m['source.original'] ?? '' }).click();
  await expect(card.locator('code[data-original]')).toHaveText(`${fact.label}: ${fact.value}`);
}

for (const language of LANGUAGES) {
  const m = MESSAGES[language];

  test(`C-20: the fact cards, source chips and quality ribbon are the server's facts and quality (${language})`, async ({
    page,
  }) => {
    test.setTimeout(180_000);
    await page.goto(`/try/prompt?lng=${language}`);
    const runId = await promptRun(page);
    const facts = (await api<Facts>(page, `/api/runs/${runId}/steps/1/facts`)).body;
    const quality = (await api<Quality>(page, `/api/runs/${runId}/steps/1/quality`)).body;
    if (!facts?.available) {
      // A step without a sealed v20 prompt (or a 404) says why and keeps its blocks as written.
      await expect(page.locator('main [data-state="no-facts"]')).toContainText(
        m[`factsReason.${facts?.reason ?? 'other'}`] ?? m['factsReason.other'] ?? '',
      );
      test.info().annotations.push({ type: 'C-20', description: `run ${runId} has no fact view (${facts?.reason})` });
      return;
    }
    if (quality?.available && quality.ribbon) {
      await expectRibbon(page.locator('main'), m, quality.ribbon);
    }
    const factsOf = (block: string) => facts.blocks.find((entry) => entry.block === block)?.facts ?? [];
    const parts = page.getByRole('list', { name: m['prompt.chunks'] ?? '' }).locator(':scope > li > button');
    await expect(parts).toHaveCount(CHUNKS.length);
    for (const [index, block] of CHUNKS.entries()) {
      const part = parts.nth(index);
      await expect(part).toContainText(m[`prompt.block.${block}`] ?? '');
      if ((await part.getAttribute('aria-expanded')) !== 'true') {
        await part.click();
      }
      // The part's chips are its facts' sources, each named by its words.
      for (const fact of factsOf(block)) {
        await expect(part).toContainText(m[`fact.source.${fact.source ?? 'NONE'}`] ?? '');
        await expectCard(page, m, fact);
      }
    }
    // A part opens below itself; nothing opened a window.
    await expect(page.getByRole('dialog')).toBeHidden();
    const folds = page.getByRole('group', { name: m['prompt.folds'] ?? '' });
    for (const block of FOLDS) {
      const fold = folds.locator('details').filter({ hasText: m[`prompt.block.${block}`] ?? '' });
      await fold.locator('summary').click();
      for (const fact of factsOf(block)) {
        await expectCard(page, m, fact);
      }
    }
    // The same case under the other bundle: offered only when the server found the run, each side under its source.
    const other = (
      await api<{
        available: boolean;
        current: { runId: string; bundle: { version: string | null } } | null;
        other: { runId: string; bundle: { version: string | null } } | null;
      }>(page, `/api/runs/${runId}/steps/1/other-bundle`)
    ).body;
    const offer = page.getByRole('button', { name: m['prompt.compare.open'] ?? '' });
    if (other?.available && other.current && other.other) {
      await offer.click();
      const sides = page.getByRole('dialog');
      await expect(sides).toContainText(m['prompt.compare.lead'] ?? '');
      await expect(sides.getByRole('region', { name: m['prompt.compare.current'] ?? '' })).toContainText(
        other.current.runId,
      );
      await expect(sides.getByRole('region', { name: m['prompt.compare.other'] ?? '' })).toContainText(
        other.other.runId,
      );
      if (other.other.bundle.version) {
        await expect(sides).toContainText(other.other.bundle.version);
      }
      await page.keyboard.press('Escape');
      await expect(sides).toBeHidden();
    } else {
      await expect(offer).toHaveCount(0);
    }
    expect(await seriousViolations(page)).toEqual([]);

    // The decision details: the ribbon on the summary, and the bundle, seal and inspection on "original and checks".
    await page.goto(`/run/${runId}/detail?lng=${language}`);
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('tab')).toHaveCount(6);
    if (quality?.available && quality.ribbon) {
      await expectRibbon(dialog, m, quality.ribbon);
    }
    await dialog.getByRole('tab', { name: m['detail.tab.original'] ?? '' }).click();
    if (quality?.bundle?.version) {
      await expect(dialog).toContainText(quality.bundle.version);
    }
    if (quality?.seal) {
      await expect(dialog).toContainText(m['detail.verify.sealed'] ?? '');
      await expect(dialog).toContainText(quality.seal.packageId);
    } else {
      await expect(dialog).toContainText(m['detail.verify.sealNone'] ?? '');
    }
    // The seal check: the inspector's seal integrity row; the sentence only when it found no mismatch, and never a
    // claim that the input was drawn again.
    const sealPart = dialog.getByRole('region', { name: m['detail.verify.sealCheck'] ?? '' });
    const sealRow = quality?.inspection?.checks.find((check) => check.code === 'SEAL_INTEGRITY') ?? null;
    if (sealRow) {
      await expect(sealPart).toContainText(
        format(m['detail.verify.sealCheckCounts'], {
          matched: sealRow.matched,
          mismatched: sealRow.mismatched,
          unverifiable: sealRow.unverifiable,
        }),
      );
      await expect(sealPart).toContainText(
        (sealRow.mismatched === 0 ? m['detail.verify.sealSame'] : m['detail.verify.sealCheckFailed']) ?? '',
      );
      if (quality?.seal?.packageHash) {
        await expect(sealPart).toContainText(quality.seal.packageHash);
      }
    } else {
      await expect(sealPart).toContainText(m['detail.verify.sealCheckNone'] ?? '');
    }
    if (quality?.inspection) {
      await expect(dialog).toContainText(
        format(m['detail.verify.inspected'], { verdict: m[`quality.verdict.${quality.inspection.verdict}`] ?? '' }),
      );
      await dialog.getByText(m['detail.verify.byCheck'] ?? '', { exact: true }).click();
      const rows = dialog.locator('tbody > tr');
      await expect(rows).toHaveCount(quality.inspection.checks.length);
      // The failed checks first.
      const failed = quality.inspection.checks.filter((check) => check.mismatched > 0).length;
      for (let index = 0; index < quality.inspection.checks.length; index += 1) {
        if (index < failed) {
          await expect(rows.nth(index)).toHaveAttribute('data-failed', 'true');
        } else {
          await expect(rows.nth(index)).not.toHaveAttribute('data-failed');
        }
      }
    } else {
      await expect(dialog).toContainText(m['detail.verify.inspectionNone'] ?? '');
    }
    expect(await seriousViolations(page)).toEqual([]);
  });

  test(`C-23: every prompt-quality number has its denominator, the measured date and its interval (${language})`, async ({
    page,
  }) => {
    await page.goto(`/benchmark/prompt?lng=${language}`);
    const answer = await api<{
      measuredAt: string;
      delivery: Rate;
      reaction: { direction: Rate };
      invariance: { firstStepFacts: Rate; decisionChanges: number };
      injection: { changed: number; unchanged: Rate };
      accuracy: Rate;
      consistency: Rate;
      reasonMatch: Rate;
    }>(page, '/api/benchmark/prompt-quality');
    const views = page.getByRole('list', { name: m['benchBar.views'] ?? '' });
    await expect(views.getByRole('link', { name: m['benchBar.view.prompt'] ?? '' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    if (answer.status === 404) {
      await expect(page.locator('main')).toContainText(m['promptQuality.notMeasured'] ?? '');
      await expect(page.getByRole('region', { name: m['promptQuality.cards'] ?? '' })).toHaveCount(0);
      expect(await seriousViolations(page)).toEqual([]);
      return;
    }
    expect(answer.status).toBe(200);
    const view = answer.body;
    if (!view) {
      throw new Error('missing: the prompt-quality view');
    }
    const interval = (rate: Rate) => format(m['benchmark.interval'], { low: percent(rate.low), high: percent(rate.high) });
    const cards = page.getByRole('region', { name: m['promptQuality.cards'] ?? '' });
    const shown: readonly (readonly [string, Rate, string])[] = [
      ['delivery', view.delivery, `${view.delivery.hits}/${view.delivery.total}`],
      ['reaction', view.reaction.direction, percent(view.reaction.direction.rate)],
      [
        'invariance',
        view.invariance.firstStepFacts,
        format(m['promptQuality.card.invariance.value'], { n: view.invariance.decisionChanges }),
      ],
      [
        'injection',
        view.injection.unchanged,
        format(m['promptQuality.card.injection.value'], {
          n: view.injection.changed,
          total: view.injection.unchanged.total,
        }),
      ],
    ];
    for (const [name, rate, value] of shown) {
      const card = cards.locator(`[data-card="${name}"]`);
      await expect(card).toContainText(value);
      // The denominator: the value is a fraction, or the card names its sample.
      await expect(card).toContainText(`${rate.hits}/${rate.total}`);
      await expect(card).toContainText(interval(rate));
      if (rate.preliminary) {
        await expect(card).toContainText(m['benchmark.preliminary'] ?? '');
      }
    }
    const more = page.getByRole('list', { name: m['promptQuality.more'] ?? '' });
    for (const name of ['accuracy', 'reasonMatch', 'consistency'] as const) {
      const line = more.locator(`[data-more="${name}"]`);
      await expect(line).toContainText(format(m[`promptQuality.more.${name}`], { rate: percent(view[name].rate) }));
      await expect(line).toContainText(`${view[name].hits}/${view[name].total}`);
      await expect(line).toContainText(interval(view[name]));
    }
    await expect(page.locator('main')).toContainText(
      format(m['promptQuality.measured'], { date: view.measuredAt.slice(0, 10) }),
    );
    expect(await seriousViolations(page)).toEqual([]);
  });
}

test('C-21: every reason code leads to the fact card of its fact ID, a reason without one says no link', async ({
  page,
}) => {
  test.setTimeout(RUN_TIMEOUT + 240_000);
  // One live try 1 run, sent as the experience e2e sends it.
  await page.goto('/try/attacker/predict?lng=ko');
  const options = (await api<{ cases: { key: string; requests: { items: number }[] }[] }>(page, '/api/lab/options'))
    .body;
  const a3 = options?.cases.find((candidate) => candidate.key === 'A3');
  const ko = MESSAGES.ko;
  await page.getByText(ko['e1.predict.CHALLENGE'] ?? '', { exact: true }).first().click();
  await page.getByText(ko['e1.predict.existing.SOME'] ?? '', { exact: true }).click();
  await page
    .getByRole('button', {
      name: format(ko['e1.predict.send'], { items: (a3?.requests[0]?.items ?? 0).toLocaleString('ko-KR') }),
    })
    .click();
  await page.waitForURL(/\/try\/attacker\/run/);
  await page.getByRole('link', { name: ko['e1.next.result'] ?? '' }).waitFor({ timeout: RUN_TIMEOUT });
  const live = (await api<{ runId: string }>(page, '/api/live/runs/current')).body;
  const runId = live?.runId ?? '';
  const quality = await settled<Quality>(page, `/api/runs/${runId}/steps/1/quality`);
  const facts = (await api<Facts>(page, `/api/runs/${runId}/steps/1/facts`)).body;
  expect(quality?.available, 'quality view of the run').toBe(true);
  const codes = quality?.reasonCodes ?? [];
  // The links are the model's own answer: the reason codes of the recorded answer, each with the fact it cites.
  const exchanges = (
    await api<{ calls: { answer: string | null }[] }>(page, `/api/runs/${runId}/steps/1/exchanges`)
  ).body;
  const answer = exchanges?.calls.at(-1)?.answer ?? null;
  if (answer) {
    const recorded = (JSON.parse(answer) as { reasonCodes?: { code: string; fact: string | null }[] }).reasonCodes;
    if (recorded) {
      expect(codes.map((code) => [code.code, code.fact ?? null])).toEqual(
        recorded.map((code) => [code.code, code.fact ?? null]),
      );
    }
  }
  const received = new Map(
    (facts?.available ? facts.blocks : []).flatMap((entry) =>
      entry.facts.filter((fact) => fact.factId !== null).map((fact) => [fact.factId ?? '', fact] as const),
    ),
  );
  for (const language of LANGUAGES) {
    const m = MESSAGES[language];
    await page.goto(`/try/attacker/reason?lng=${language}`);
    const chain = page.getByRole('group', { name: m['reasonChain.title'] ?? '' });
    if (codes.length === 0) {
      await expect(chain).toHaveCount(0);
      continue;
    }
    const rows = chain.locator('ol > li');
    await expect(rows).toHaveCount(codes.length);
    for (const [index, code] of codes.entries()) {
      const row = rows.nth(index);
      await expect(row.locator('code[data-original]').last()).toHaveText(
        code.fact ? `${code.code} · ${code.fact}` : code.code,
      );
      const fact = code.fact ? received.get(code.fact) : undefined;
      if (fact) {
        const card = row.locator(`[data-fact="${code.fact}"]`);
        await expect(card).toContainText(labelWords(m, fact.label));
        await row.getByRole('button', { name: new RegExp(m[`reasonCode.${code.code}`]?.slice(0, 8) ?? code.code) }).click();
        await expect(card).toHaveAttribute('data-highlight', 'true');
      } else if (code.fact !== null && !facts?.available) {
        await expect(row).toContainText(m['reasonChain.noCard'] ?? '');
      } else {
        await expect(row).toContainText(m['reasonChain.noLink'] ?? '');
      }
    }
    await expect(chain).toContainText(verdictWords(m, (await api<{ verdicts: { score: { finalAction: string | null } }[] }>(page, `/api/runs/${runId}/score`)).body?.verdicts[0]?.score.finalAction ?? null));
    expect(await seriousViolations(page)).toEqual([]);
  }
});

test("C-22: the lab result's changed lines are the server's delta of a run that changed one condition", async ({
  page,
}) => {
  test.setTimeout(2 * RUN_TIMEOUT + 240_000);
  const ko = MESSAGES.ko;
  const send = async (address: string) => {
    await page.goto(address);
    await page.getByLabel(ko['labSend.calls.ATTACK'] ?? '', { exact: true }).check();
    await page.getByRole('button', { name: ko['labSend.send'] ?? '' }).click();
    await page.waitForURL(/sent=/);
    await page.getByRole('link', { name: ko['labSend.toResult'] ?? '' }).waitFor({ timeout: RUN_TIMEOUT });
    await page.getByRole('link', { name: ko['labSend.toResult'] ?? '' }).click();
    await page.waitForURL(/\/lab\/result\?run=/);
    return new URL(page.url()).searchParams.get('run') ?? '';
  };
  // The case as designed first, then the same case with only the approval record taken away.
  await send('/lab/send?case=A3T&lng=ko');
  const runId = await send('/lab/send?case=A3T&approval=false&lng=ko');
  const delta = await settled<{
    condition: string | null;
    value: string | null;
    available: boolean;
    steps: {
      stepNo: number;
      changed: { label: string; before: string[]; after: string[] }[];
      unexpected: string[];
      valueMatches: boolean | null;
      passed: boolean;
      notCompared: string | null;
      unchangedLines?: number | null;
      notLookedUp?: string | null;
    }[];
  }>(page, `/api/lab/runs/${runId}/delta`);
  expect(delta?.available, 'delta of the changed run').toBe(true);
  expect(delta?.condition).toBe('approval');
  const resultAddress = page.url().replace(/&?lng=\w+/, '');
  for (const language of LANGUAGES) {
    const m = MESSAGES[language];
    await page.goto(`${resultAddress}${resultAddress.includes('?') ? '&' : '?'}lng=${language}`);
    const section = page.getByRole('region', { name: m['labDelta.title'] ?? '' });
    await expect(section).toContainText(m[`lab.fieldInline.${delta?.condition ?? ''}`] ?? '');
    const flows = section.locator('[data-step]');
    await expect(flows).toHaveCount(delta?.steps.length ?? 0);
    for (const [index, step] of (delta?.steps ?? []).entries()) {
      const flow = flows.nth(index);
      const lines = flow.getByRole('list', { name: m['labDelta.lines'] ?? '' });
      // N-DLV-4: a passed step whose condition the request's work does not look up says so in one line.
      const notLookedUp = step.passed && step.notLookedUp ? step.notLookedUp : null;
      if (step.changed.length === 0 && notLookedUp === null) {
        await expect(flow).toContainText(m['labDelta.none'] ?? '');
      } else if (step.changed.length > 0) {
        await expect(lines.locator(':scope > li')).toHaveCount(step.changed.length);
      }
      for (const line of step.changed) {
        await expect(lines).toContainText(labelWords(m, line.label));
        await expect(lines).toContainText(
          `${line.label}: ${line.before.join(' | ') || '-'} → ${line.after.join(' | ') || '-'}`,
        );
      }
      await expect(lines.locator('li[data-unexpected]')).toHaveCount(
        step.changed.filter((line) => step.unexpected.includes(line.label)).length,
      );
      if (step.notCompared !== null) {
        // A step the server did not compare says so and is never shown as passed.
        await expect(flow).toContainText(m[`labDelta.notCompared.${step.notCompared}`] ?? '');
        await expect(flow).not.toContainText(m['labDelta.passed'] ?? '');
      } else if (notLookedUp !== null) {
        await expect(flow).toContainText(m[`labDelta.notLookedUp.${notLookedUp}`] ?? '');
        await expect(flow).not.toContainText(m['labDelta.none'] ?? '');
      } else if (step.passed) {
        // The other lines are counted when the server says how many.
        await expect(flow).toContainText(
          typeof step.unchangedLines === 'number'
            ? format(m['labDelta.passedCount'], { n: step.unchangedLines })
            : (m['labDelta.passed'] ?? ''),
        );
      } else {
        await expect(flow).toContainText(m['labDelta.failed'] ?? '');
        for (const label of step.unexpected) {
          await expect(flow.getByRole('list', { name: m['labDelta.unexpected'] ?? '' })).toContainText(label);
        }
      }
      if (step.notCompared === null && step.valueMatches === false) {
        await expect(flow).toContainText(m['labDelta.valueMissed'] ?? '');
      }
    }
    expect(await seriousViolations(page)).toEqual([]);
  }
});
