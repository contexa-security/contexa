import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../../i18n';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { MINIMUM_ACTION_PLAIN } from '../inside/promptSections';
import { DecisionDetailModal } from './DecisionDetail';
import { STEPS } from './detailWords';
import { DETAIL_TABS } from './useDetail';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

const RUN = 'run-0a1b2c3d4e5f';

/** The old column of the term table (설계서 43~45장, F3-6): words no visitor sees; the record's originals aside. */
const BANNED = [
  '계정을 훔친 사람',
  '진짜 직원',
  '본인 확인',
  '규칙 조여 보기',
  '정상 업무 막음',
  '업무를 막음',
  '평소 모습',
  '시간·건수 제한',
  '웹 방화벽',
  '로그인·권한 확인',
  '결재·담당 확인',
  '판정 자세히 보기',
  '응답 전에 막기',
  '다음 요청부터 막기',
  '보류(관리자 검토)',
  '출처 문장',
];

/** The minimum action rule lines exactly as a v20 system text states them (the screen matches whole lines). */
const P1 = required(MINIMUM_ACTION_PLAIN.find((rule) => rule.key === 'gRules.plain.minP1')).starts;
const P3 = required(MINIMUM_ACTION_PLAIN.find((rule) => rule.key === 'gRules.plain.minP3')).starts;
const MINIMUM = required(MINIMUM_ACTION_PLAIN.find((rule) => rule.key === 'gRules.plain.minimum')).starts;

// Every value below is this test's own, in the shape the portal returns; the window must show them as they are.
function anatomy(overrides: Readonly<Record<string, unknown>> = {}) {
  return {
    builderVersion: 1,
    runId: RUN,
    stepNo: 1,
    requestId: 'req-1',
    operation: 'EXPORT',
    recovery: null,
    context: {
      usualVsNow: [],
      usual: null,
      labelMatrix: {},
      request: null,
      learning: null,
      resource: null,
      company: null,
      coverage: null,
      rag: { ragAuthorizedDocumentCount: 5 },
      template: null,
    },
    interpretation: {
      calls: [
        {
          callNo: 1,
          model: 'model-test',
          requestOptions: null,
          finishReason: 'stop',
          promptTokens: 6393,
          completionTokens: 326,
          reasoningTokens: 171,
          elapsedMs: 4092,
          success: true,
          failure: null,
          answer: null,
          parsedAnswer: null,
        },
      ],
      recorded: {
        proposedAction: 'ESCALATE',
        finalAction: 'ESCALATE',
        riskScore: null,
        confidence: null,
        reasoning: 'No approval covers the critical export.',
        reasoningCode: null,
        mitre: null,
        unresolved: false,
        failureType: null,
        fallbackCategory: null,
        applied: 'BEFORE_RESPONSE',
        evidenceRefs: [],
      },
      modelReasoning: null,
      reasoningDiffers: false,
      contractLines: [],
      timings: {
        promptBuildMs: null,
        ragVectorMs: 4,
        llmLatencyMs: 7545,
        totalAnalysisMs: 7545,
        events: [
          {
            type: 'LAYER2_COMPLETE',
            layer: 'LAYER2',
            action: 'ESCALATE',
            elapsedMs: 2,
            observedAt: null,
            reasoning: 'The deeper pass agrees.',
            riskScore: null,
            confidence: null,
          },
        ],
      },
      timeline: [],
      sinceStartMs: [],
      promptTokens: 6393,
      completionTokens: 326,
    },
    truth: {
      classification: 'THREAT',
      allowedEngineActions: ['BLOCK', 'CHALLENGE', 'ESCALATE'],
      rationale: { ko: '시험용으로 정한 이유 문장', en: 'A reason set for the test' },
      counterpoint: null,
      truthSource: 'RUN_SNAPSHOT',
      verdict: {
        score: { result: 'RIGHT', finalAction: 'ESCALATE', applicable: true, applied: 'BEFORE_RESPONSE' },
        source: 'MODEL',
        proposedAction: 'ESCALATE',
      },
      business: { result: 'STOPPED', exposedItems: 0, worstStep: null },
      businessCorrect: true,
      scenarioSha256: '4f9ea71da0a6252f92e7',
    },
    learning: null,
    juxtaposition: {
      departures: [],
      companyFacts: ['line one', 'line two', 'line three'],
      sensitivity: 'CRITICAL',
      modelReasoning: null,
      recordedReasoning: null,
      coreAdverseLabels: [{ label: 'policysatisfied', condition: 'NOT_SATISFIED', values: [], met: true }],
      adverseMet: 1,
      adverseChecked: 6,
    },
    promptLines: {
      layout: 'V20_BLOCKS',
      total: 167,
      system: 108,
      user: 59,
      systemPhysical: 117,
      userPhysical: 66,
      sections: [],
      bundles: [],
    },
    figures: {
      workProfileWindow: '7d',
      workProfileObservations: 24,
      baselineBefore: 24,
      baselineAfter: 25,
      baselineAdded: 1,
      documentsBefore: 24,
      documentsAfter: 24,
      documentsForThisRequest: 0,
      departureCount: 4,
    },
    ...overrides,
  };
}

const score = {
  runId: RUN,
  scenarioKey: 'A3',
  scenarioVersion: 1,
  status: 'COMPLETED',
  truthSource: 'RUN_SNAPSHOT',
  truth: { classification: 'THREAT', allowedEngineActions: ['BLOCK', 'CHALLENGE', 'ESCALATE'] },
  definedSteps: 1,
  executedSteps: 1,
  business: {},
  correct: {},
  rightControls: 3,
  verdicts: [
    {
      score: {
        stepNo: 1,
        finalAction: 'ESCALATE',
        result: 'RIGHT',
        applicable: true,
        friction: false,
        applied: 'BEFORE_RESPONSE',
      },
      source: 'MODEL',
      proposedAction: 'ESCALATE',
      decidedAt: '2026-10-16T01:46:53.635544Z',
    },
  ],
  checks: [],
  title: { ko: '시험 상황', en: 'Test situation' },
};

const result = {
  layers: [{ control: 'D', evidence: { deliveredItems: 0 }, httpStatus: 423, ruleId: 'R-TEST' }],
};

const received = {
  runId: RUN,
  stepNo: 1,
  startedAt: null,
  companyTime: null,
  usualVsNow: [
    { dimension: 'accessHour', now: '03', inUsual: 'false', labels: ['DeviationsFromBaseline'] },
    { dimension: 'dayOfWeek', now: 'Wed', inUsual: 'true', labels: ['SameAsBaseline'] },
    { dimension: 'network', now: '10.40.12.0/24', inUsual: 'true', labels: ['SameAsBaseline'] },
    { dimension: 'rate', now: '1', inUsual: 'UNKNOWN: not compared', labels: [] },
  ],
  usual: { accessHour: { label: 'UsualHours', values: ['10', '11'] } },
  departures: [],
  departureCount: 1,
  companyAdverse: [],
  companyAdverseCount: 0,
  company: {},
  companyFacts: [],
  businessFacts: [],
  sensitivity: 'CRITICAL',
  boundary: null,
  minimumRules: {
    rules: [
      { code: 'MIN_P1_IDENTITY_DEVIATION', line: P1, floor: 'CHALLENGE', met: false },
      { code: 'MIN_P3_POLICY_NOT_SATISFIED', line: P3, floor: 'ESCALATE', met: true },
    ],
    applies: true,
  },
};

function exchanges(kept = true) {
  return {
    runId: RUN,
    stepNo: 1,
    kept,
    missing: kept ? null : 'PAST_RETENTION',
    calls: kept
      ? [
          {
            callNo: 1,
            model: 'model-test',
            systemPrompt: [
              'ALLOW = coherent legitimate story with low unresolved risk.',
              'CHALLENGE = a concrete, resolvable risk that requires additional verification.',
              'ESCALATE = materially incomplete, conflicting, or ambiguous story.',
              'BLOCK = clearly harmful or malicious story.',
              `${MINIMUM} ALLOW, CHALLENGE, ESCALATE, BLOCK)`,
              P1,
              P3,
            ].join('\n'),
            userPrompt: '=== REQUEST (time zone UTC) ===\nAction: EXPORT',
            answer: '{"action":"ESCALATE"}',
            finishReason: 'stop',
            providerResponse: '{"id":"masked"}',
            maskedPlaces: 1,
            capturedAt: null,
          },
        ]
      : [],
  };
}

function fact(line: number, label: string, value: string) {
  return { line, factId: `F${line}`, label, value, source: 'HOST', grades: ['HOST'] };
}

const facts = {
  runId: RUN,
  stepNo: 1,
  available: true,
  reason: null,
  bundle: null,
  blocks: [
    {
      block: 'DECISION_FACTS',
      facts: [
        fact(21, 'Policy', 'EXPORT_APPROVAL requires a covering approval'),
        fact(22, 'PolicySatisfied', 'no — no approval for GB-500'),
        fact(23, 'Assignment', 'not assigned to GB-500'),
        fact(24, 'Ticket', 'none'),
        fact(25, 'OnCall', 'no'),
        fact(26, 'Travel', 'none'),
      ],
    },
    { block: 'REQUEST', facts: [fact(3, 'Action', 'EXPORT')] },
  ],
};

const quality = {
  available: true,
  reason: null,
  bundle: {
    version: '2026.10.16-v20.23',
    hash: '44b1c05d0a40a73f69c6',
    selectionSource: 'CONFIGURATION',
    layout: null,
  },
  seal: { packageId: 'pkg-test', packageHash: 'hash-test', capturedAt: '2026-10-16T01:46:53Z' },
  inspection: {
    verdict: 'INCOMPLETE',
    inspectorVersion: 'prompt-inspector/22',
    inspectedAt: '2026-10-17T08:23:31Z',
    checks: [
      { code: 'SEAL_INTEGRITY', matched: 10, mismatched: 0, unverifiable: 0, mismatches: [] },
      {
        code: 'FACT_ACCURACY',
        matched: 3,
        mismatched: 1,
        unverifiable: 0,
        mismatches: [
          {
            block: null,
            entry: 'Ticket',
            factId: 'F24',
            line: 24,
            expected: 'none',
            actual: 'T-1',
            reason: null,
          },
        ],
      },
      { code: 'SAME_FACT', matched: 0, mismatched: 0, unverifiable: 1, mismatches: [] },
    ],
  },
  reasonCodes: [],
  ribbon: {
    facts: 49,
    withSource: 49,
    factAccuracy: { matched: 0, total: 0 },
    contradictions: 0,
    unknown: 2,
  },
};

const noOtherBundle = { available: false, reason: 'NONE', current: null, other: null };

const teasers = {
  computedAt: '2026-10-18T09:37:23Z',
  teasers: [
    {
      key: 'CHALLENGE_OUTCOMES',
      values: {
        outcomes: { ABANDONED: 84, ANSWERED: 214, EXPIRED: 127, NO_MAILBOX: 1847, 'code request 500': 2 },
        total: 2274,
        resumed: 200,
      },
      holds: null,
      source: { kind: 'CHALLENGES', ref: 'forced_action is null' },
      missing: null,
    },
  ],
};

let served: Record<string, unknown>;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  const base = `/api/runs/${RUN}`;
  served = {
    [`${base}/score`]: score,
    [`${base}/steps/1/anatomy`]: anatomy(),
    [`${base}/steps/1/result`]: result,
    [`${base}/steps/1/received`]: received,
    [`${base}/steps/1/exchanges`]: exchanges(),
    [`${base}/steps/1/facts`]: facts,
    [`${base}/steps/1/quality`]: quality,
    [`${base}/steps/1/other-bundle`]: noOtherBundle,
    '/api/teasers': teasers,
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = served[url];
      return new Response(body === undefined ? null : JSON.stringify(body), {
        status: body === undefined ? 404 : 200,
      });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open(tab: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/?modal=detail&detailRun=${RUN}&detailStep=1&detailTab=${tab}`]}>
        <DecisionDetailModal />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The tab's body zone, once it has drawn. */
async function body(): Promise<HTMLElement> {
  const dialog = await screen.findByRole('dialog');
  await waitFor(() => expect(dialog.querySelector('[data-zone="body"]')).not.toBeNull());
  return required(dialog.querySelector<HTMLElement>('[data-zone="body"]'), 'body zone');
}

/** What a visitor reads in the window, the record's own originals left out (as the automatic check reads it). */
function visibleText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  clone.querySelectorAll('[data-original]').forEach((element) => element.remove());
  return clone.textContent ?? '';
}

describe('decision details: the window (RO-1)', () => {
  it('has seven tabs in order, the tab buttons outside the measured zones', async () => {
    open('summary');
    const dialog = await screen.findByRole('dialog');
    const tabs = await within(dialog).findAllByRole('tab');
    expect(tabs.map((tab) => tab.textContent)).toEqual(
      DETAIL_TABS.map((tab) => word(`detail.r7.tab.${tab}`)),
    );
    await body();
    for (const tab of tabs) {
      expect(tab.closest('[data-zone]')).toBeNull();
    }
  });

  it('names the situation in the plain name the lab and the benchmark show (V-45)', async () => {
    open('summary');
    const title = await screen.findByText(word('bench.r7.caseName.A3'), { exact: false });
    expect(title.closest('h2')).toHaveTextContent(word('detail.r7.title'));
    expect(screen.queryByText('시험 상황')).not.toBeInTheDocument();
  });

  /**
   * docs/agent Agent중심-화면 AS-1: the window says who sent the requests, as the stored record says: the sender of the
   * run's agent work when it has one, a person when the run has none. It is never worked out from the screen it was
   * opened from.
   */
  it("says who sent the requests from the run's agent record: an agent on a delegation, else a person", async () => {
    served[`/api/runs/${RUN}/agent`] = { runId: RUN, sender: 'DELEGATED_AGENT', steps: [] };
    open('summary');
    const title = (await screen.findByText(word('bench.r7.caseName.A3'), { exact: false })).closest('h2');
    expect(await within(required(title)).findByLabelText('보내는 쪽: 위임 에이전트')).toBeInTheDocument();
  });

  it('says a person sent the requests of a run that has no agent record', async () => {
    open('summary');
    const title = (await screen.findByText(word('bench.r7.caseName.A3'), { exact: false })).closest('h2');
    expect(await within(required(title)).findByLabelText('보내는 쪽: 사람')).toBeInTheDocument();
  });

  it("names a situation without a plain name as the server stored it, as the record's own words", async () => {
    served[`/api/runs/${RUN}/score`] = { ...score, scenarioKey: 'X9' };
    open('summary');
    const name = await screen.findByText('시험 상황');
    expect(name).toHaveAttribute('data-original');
    expect(name.closest('h2')).toHaveTextContent(word('detail.r7.title'));
  });

  // B-04: the window keeps its size from tab to tab; a tab longer than it scrolls inside, by the keyboard too.
  it('scrolls a long tab inside its own panel, which the keyboard reaches', async () => {
    open('process');
    await body();
    expect(screen.getByRole('tabpanel')).toHaveAttribute('tabindex', '0');
  });

  it.each(DETAIL_TABS)('shows no old term in the %s tab', async (tab) => {
    open(tab);
    const zone = await body();
    await waitFor(() => expect(zone.textContent).not.toBe(''));
    const dialog = screen.getByRole('dialog');
    const text = visibleText(dialog);
    expect(BANNED.filter((term) => text.includes(term))).toEqual([]);
  });
});

describe('decision details: the summary collects each number with its source (RO-1)', () => {
  // 판정층 8절 9: a block that cut a streamed response applied while it was sent (the step result's timing).
  it('says a block that cut the stream applied while the response was sent', async () => {
    const evidence = required(result.layers[0], 'the D layer').evidence;
    Object.assign(evidence, { timing: 'MID_RESPONSE', deliveredItems: 744 });
    try {
      open('summary');
      const table = await screen.findByRole('table', { name: word('detail.r7.summary.table') });
      await waitFor(() => expect(table).toHaveTextContent(fill('detail.r7.summary.items', { items: '744' })));
      expect(table).toHaveTextContent(word('detail.r7.applied.MID_RESPONSE'));
    } finally {
      Object.assign(evidence, { timing: null, deliveredItems: 0 });
    }
  });

  it("shows the server's values, each with where it comes from", async () => {
    open('summary');
    const table = await screen.findByRole('table', { name: word('detail.r7.summary.table') });
    const row = (key: string) =>
      required(
        within(table)
          .getAllByRole('row')
          .find((candidate) => candidate.textContent?.startsWith(word(`detail.r7.summary.row.${key}`))),
        key,
      );
    await waitFor(() =>
      expect(row('out')).toHaveTextContent(fill('detail.r7.summary.items', { items: '0' })),
    );
    expect(row('judgment')).toHaveTextContent(word('verdict.review'));
    expect(row('judgment')).toHaveTextContent(word('detail.r7.from.decision'));
    expect(row('when')).toHaveTextContent(
      `${word('detail.r7.applied.BEFORE_RESPONSE')} · ${fill('detail.r7.seconds', { s: '7.5' })}`,
    );
    expect(row('out')).toHaveTextContent(word('detail.r7.from.response'));
    expect(row('learned')).toHaveTextContent(
      fill('detail.r7.summary.learnedValue', { before: '24', after: '25' }),
    );
    expect(row('learned')).toHaveTextContent(word('detail.r7.from.learning'));
    // L-27: a request stopped by a judgment other than a block names that judgment beside "stopped".
    expect(row('right')).toHaveTextContent(
      `${word('detail.r7.expected.stop')} · ${word('detail.r7.result.rightStop')} · ${fill('detail.r7.summary.judged', { verdict: word('verdict.review') })}`,
    );
    expect(row('right')).toHaveTextContent(word('detail.r7.from.case.RUN_SNAPSHOT'));
    expect(row('learned')).not.toHaveTextContent(word('detail.r7.summary.notLearned'));
  });

  // L-27: the learned count that stayed the same says why when the published learning rule explains it.
  it('says why the learned count stayed the same for a request held for a check or blocked, and names no reason otherwise', async () => {
    const summaryRow = async (key: string) => {
      const table = await screen.findByRole('table', { name: word('detail.r7.summary.table') });
      return required(
        within(table)
          .getAllByRole('row')
          .find((candidate) => candidate.textContent?.startsWith(word(`detail.r7.summary.row.${key}`))),
        key,
      );
    };
    const decided = (finalAction: string, extra: Readonly<Record<string, unknown>> = {}) =>
      anatomy({
        interpretation: {
          ...anatomy().interpretation,
          recorded: { ...anatomy().interpretation.recorded, finalAction, proposedAction: finalAction },
        },
        figures: { ...anatomy().figures, baselineBefore: 24, baselineAfter: 24 },
        ...extra,
      });
    served[`/api/runs/${RUN}/steps/1/anatomy`] = decided('CHALLENGE', {
      recovery: { challenge: { answered: false, reason: 'NO_MAILBOX' }, release: null },
    });
    const first = open('summary');
    await waitFor(async () =>
      expect(await summaryRow('learned')).toHaveTextContent(word('detail.r7.summary.notLearned')),
    );
    first.unmount();
    served[`/api/runs/${RUN}/steps/1/anatomy`] = decided('BLOCK');
    const second = open('summary');
    await waitFor(async () =>
      expect(await summaryRow('learned')).toHaveTextContent(word('detail.r7.summary.notLearned')),
    );
    // A block is the plain way to stop: the row needs no judgment beside it.
    expect(await summaryRow('right')).not.toHaveTextContent(
      fill('detail.r7.summary.judged', { verdict: word('verdict.block') }),
    );
    second.unmount();
    served[`/api/runs/${RUN}/steps/1/anatomy`] = decided('ALLOW');
    open('summary');
    await waitFor(async () =>
      expect(await summaryRow('learned')).toHaveTextContent(
        fill('detail.r7.summary.learnedValue', { before: '24', after: '24' }),
      ),
    );
    expect(await summaryRow('learned')).not.toHaveTextContent(word('detail.r7.summary.notLearned'));
  });

  it('puts the record number and the time of the judgment on the source line', async () => {
    open('summary');
    await body();
    const source = required(screen.getByRole('dialog').querySelector('[data-zone="source"]'), 'source zone');
    await waitFor(() =>
      expect(source).toHaveTextContent(fill('detail.r7.record.at', { time: '2026-10-16 01:46:53' })),
    );
    expect(within(source as HTMLElement).getByText(RUN)).toHaveAttribute('data-original');
  });

  it("states that a free reason is the model's own sentence, kept in the original record, not the English itself", async () => {
    open('summary');
    expect(await screen.findByText(word('detail.r7.summary.free'))).toBeInTheDocument();
    expect(screen.queryByText('No approval covers the critical export.')).toBeNull();
  });

  // V-03: the free reason's line leads to the sentence it speaks of, one press away (V-6 keeps the English there).
  it('opens the original record on the reason the AI wrote from the summary', async () => {
    open('summary');
    fireEvent.click(await screen.findByRole('button', { name: word('detail.r7.summary.toOriginal') }));
    expect(await screen.findByText('No approval covers the critical export.')).toHaveAttribute(
      'data-original',
    );
    expect(screen.getByRole('tab', { name: word('detail.r7.tab.original') })).toHaveAttribute(
      'aria-selected',
      'true',
    );
  });

  it('says why a request was not judged again, with the app answer as recorded', async () => {
    served[`/api/runs/${RUN}/steps/1/anatomy`] = anatomy({
      interpretation: {
        ...anatomy().interpretation,
        recorded: { ...anatomy().interpretation.recorded, finalAction: null, proposedAction: null },
      },
      truth: { ...anatomy().truth, verdict: { ...anatomy().truth.verdict, source: 'PRIOR_DECISION' } },
    });
    open('summary');
    expect(await screen.findByText(word('detail.r7.notAnalysed.PRIOR_DECISION'))).toBeInTheDocument();
    expect(await screen.findByText('423 · R-TEST')).toHaveAttribute('data-original');
  });
});

describe("decision details: the process is screen 3-2's nine steps (RO-1, RO-11)", () => {
  it("names the steps as 3-2 does, each with this request's value", async () => {
    open('process');
    const list = await screen.findByRole('list', { name: word('detail.r7.process.figure') });
    const items = within(list).getAllByRole('listitem');
    expect(items).toHaveLength(STEPS.length);
    STEPS.forEach((id, index) => {
      expect(items[index]).toHaveTextContent(word(`p3.how.step.${id}.name`));
    });
    const value = (id: (typeof STEPS)[number]) => required(items[STEPS.indexOf(id)], id);
    expect(value('request')).toHaveTextContent(
      fill('detail.r7.process.request', { action: word('detail.r7.operation.EXPORT') }),
    );
    expect(value('usual')).toHaveTextContent(fill('detail.r7.process.usual', { n: '4' }));
    expect(value('company')).toHaveTextContent(fill('detail.r7.process.company', { n: '3' }));
    expect(value('history')).toHaveTextContent(fill('detail.r7.process.history', { n: '5' }));
    // No build time was recorded, so the step states the text's lines instead.
    expect(value('prompt')).toHaveTextContent(fill('detail.r7.process.promptLines', { n: '167' }));
    expect(value('judgement')).toHaveTextContent(
      `${fill('detail.r7.process.answered', { s: '7.5' })} · ${word('detail.r7.process.second')}`,
    );
    // V-43: the engine's whole-analysis time is the AI's own time in every record, so the record step does not
    // state it again as a time "from the start".
    expect(value('decision')).toHaveTextContent(word('verdict.review'));
    expect(value('decision')).not.toHaveTextContent(fill('detail.r7.seconds', { s: '7.5' }));
    expect(value('followUp')).toHaveTextContent(word('detail.r7.process.followUpNone'));
    expect(value('learning')).toHaveTextContent(
      fill('detail.r7.process.learned', { before: '24', after: '25' }),
    );
  });

  it('says a step has no record rather than drawing a value', async () => {
    served[`/api/runs/${RUN}/steps/1/anatomy`] = anatomy({
      context: { ...anatomy().context, rag: null },
      figures: { ...anatomy().figures, departureCount: null, baselineBefore: null },
      operation: 'SOMETHING_NEW',
    });
    open('process');
    const list = await screen.findByRole('list', { name: word('detail.r7.process.figure') });
    expect(list).toHaveTextContent(word('detail.r7.process.requestOther'));
    expect(list).toHaveTextContent(word('detail.r7.process.usualNone'));
    expect(list).toHaveTextContent(word('detail.r7.process.historyNone'));
    expect(list).not.toHaveTextContent('SOMETHING_NEW');
  });
});

describe('decision details: the rules tab (RO-1, RO-8)', () => {
  it("shows the identity checks' outcomes under the identity check, in order, with the server's counts", async () => {
    open('rules');
    const total = await screen.findByText(fill('detail.r7.rules.outcomes', { total: '2,274' }), {
      exact: false,
    });
    const line = required(total.closest('span'), 'outcome line');
    const text = line.textContent ?? '';
    const parts = [
      fill('detail.r7.rules.outcome.answeredResumed', { n: '214', resumed: '200' }),
      fill('detail.r7.rules.outcome.NO_MAILBOX', { n: '1,847' }),
      fill('detail.r7.rules.outcome.ABANDONED', { n: '84' }),
      fill('detail.r7.rules.outcome.EXPIRED', { n: '127' }),
      fill('detail.r7.rules.outcome.other', { n: '2' }),
    ];
    const at = parts.map((part) => text.indexOf(part));
    expect(at.every((index) => index >= 0)).toBe(true);
    expect([...at].sort((left, right) => left - right)).toEqual(at);
    // L-43: each outcome is one piece, its name with its count, the separators between the pieces.
    for (const part of parts.slice(0, 4)) {
      expect(within(line).getByText(part)).toBeInTheDocument();
    }
    // An outcome without words of its own keeps its recorded name, as the record's own words.
    expect(within(line).getByText('code request 500')).toHaveAttribute('data-original');
  });

  it('states the overlap rule', async () => {
    open('rules');
    expect(
      await screen.findByText(word('detail.r7.rules.overlapText'), { exact: false }),
    ).toBeInTheDocument();
  });

  // V-16, V-17, V-60: the words of the rules tab say what they count and why, as the records show.
  it('names the checks as requests sent to an extra check, the mailbox outcome with its reason, and the overlap plainly', () => {
    // 2,439 counts the requests that went to an extra check (an earlier judgment's later requests too), not judgments.
    expect(word('detail.r7.rules.outcomes')).toContain('요청');
    expect(word('detail.r7.rules.outcomes')).not.toContain('요구한 추가 인증');
    // The code goes to the account owner's mailbox, which the attacker does not have (LiveRun NO_MAILBOX).
    expect(word('detail.r7.rules.outcome.NO_MAILBOX')).toContain('계정 주인');
    expect(word('detail.r7.check.NO_MAILBOX')).toContain('계정 주인');
    expect(word('detail.r7.check.NO_MAILBOX')).not.toContain('정상 사용자');
    expect(word('detail.r7.rules.overlapText')).toContain('계정');
    expect(word('detail.r7.rules.overlapText')).not.toContain('걸리고');
  });

  it("gives the request's rule lines in plain words, in order, the met one marked, the four definitions not again", async () => {
    open('rules');
    const minimum = await screen.findByText(word('detail.r7.rule.minimum'));
    const list = required(minimum.closest('ol'), 'rule lines');
    const items = within(list).getAllByRole('listitem');
    expect(items.map((item) => item.querySelector('span')?.textContent)).toEqual([
      word('detail.r7.rule.minimum'),
      word('detail.r7.rule.minP1'),
      word('detail.r7.rule.minP3'),
    ]);
    expect(items[1]).not.toHaveTextContent(word('detail.r7.rules.met'));
    expect(items[2]).toHaveTextContent(word('detail.r7.rules.met'));
    expect(list).not.toHaveTextContent(word('detail.r7.rule.ALLOW'));
  });

  it('says the text is gone past its retention and states the gist of the rules instead', async () => {
    served[`/api/runs/${RUN}/steps/1/exchanges`] = exchanges(false);
    open('rules');
    expect(await screen.findByText(word('detail.r7.rules.gone'))).toBeInTheDocument();
    expect(screen.getByText(word('gRules.line.minimum'))).toBeInTheDocument();
  });
});

describe('decision details: the text sent to the AI (RO-1)', () => {
  it("shows a part's facts by plain name with the line's value as sent, four at a time", async () => {
    open('prompt');
    const table = await screen.findByRole('table', { name: word('detail.r7.prompt.block.DECISION_FACTS') });
    expect(within(table).getAllByRole('row')).toHaveLength(5);
    expect(within(table).getByText(word('fact.label.Policy'))).toBeInTheDocument();
    expect(within(table).getByText('EXPORT_APPROVAL requires a covering approval')).toHaveAttribute(
      'data-original',
    );
    expect(within(table).getByText(word('detail.r7.plain.approvalMissing'))).toBeInTheDocument();
    expect(screen.getByText(fill('detail.r7.prompt.page', { page: 1, pages: 2 }))).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: word('detail.r7.prompt.nextPage') }));
    const next = await screen.findByRole('table', { name: word('detail.r7.prompt.block.DECISION_FACTS') });
    expect(within(next).getAllByRole('row')).toHaveLength(3);
    expect(within(next).getByText(word('fact.label.Travel'))).toBeInTheDocument();
  });

  it('moves to another part through the one chooser', async () => {
    open('prompt');
    const chooser = await screen.findByLabelText(word('detail.r7.prompt.choose'));
    fireEvent.change(chooser, { target: { value: 'REQUEST' } });
    const table = await screen.findByRole('table', { name: word('detail.r7.prompt.block.REQUEST') });
    expect(within(table).getByText('EXPORT')).toHaveAttribute('data-original');
  });

  it('never shows facts as matching their source when the inspection compared none', async () => {
    open('prompt');
    expect(await screen.findByText(word('detail.r7.prompt.check.accuracyNone'))).toBeInTheDocument();
    expect(
      screen.getByText(fill('detail.r7.prompt.check.adverse', { total: '6', met: '1' }), { exact: false }),
    ).toBeInTheDocument();
  });

  // P-21: a fact without its source is named as such and is one press away, not a bare cross.
  it('names a missing source and leads to the line without one', async () => {
    served[`/api/runs/${RUN}/steps/1/facts`] = {
      ...facts,
      blocks: [
        facts.blocks[0],
        { block: 'REQUEST', facts: [{ ...fact(3, 'Action', 'EXPORT'), source: null }] },
      ],
    };
    served[`/api/runs/${RUN}/steps/1/quality`] = {
      ...quality,
      ribbon: { ...quality.ribbon, facts: 7, withSource: 6 },
    };
    open('prompt');
    const checks = await screen.findByRole('list', { name: word('detail.r7.prompt.check.title') });
    expect(within(checks).getByText(word('detail.r7.prompt.check.sourceMissing'))).toBeInTheDocument();
    fireEvent.click(within(checks).getByRole('button', { name: word('detail.r7.prompt.check.toMissing') }));
    const table = await screen.findByRole('table', { name: word('detail.r7.prompt.block.REQUEST') });
    expect(table.querySelector('tr[data-line="3"]')).toHaveAttribute('data-target', 'true');
    expect(screen.getByLabelText(word('detail.r7.prompt.choose'))).toHaveValue('REQUEST');
  });

  it('offers the other bundle only when the server found one', async () => {
    open('prompt');
    const chooser = await screen.findByLabelText(word('detail.r7.prompt.choose'));
    expect(
      within(chooser).queryByRole('option', { name: word('detail.r7.prompt.block.compare') }),
    ).toBeNull();
  });
});

describe('decision details: what Contexa received (RO-1)', () => {
  it("names the items the comparison table leaves out by the engine's own labels", async () => {
    open('received');
    await body();
    expect(
      await screen.findByText(
        fill('detail.r7.received.same', { names: `${word('dim.dayOfWeek')} · ${word('dim.network')}` }),
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(fill('detail.r7.received.unknown', { names: word('dim.rate') })),
    ).toBeInTheDocument();
    // V-62: the engine counts a value it has seen even once as usual (Deviation: different = never seen).
    expect(word('detail.r7.received.same')).toContain('본 적');
  });

  // R-07, V-41: a missing approval the company policy does not ask for is not flagged; the tab says why.
  it('says a missing approval is not flagged when the company policy needs none for this export', async () => {
    served[`/api/runs/${RUN}/steps/1/received`] = {
      ...received,
      company: { approvalRequired: false, approvalMissing: false },
      businessFacts: [{ code: 'NO_APPROVAL', value: null }],
    };
    open('received');
    expect(await screen.findByText(word('detail.r7.received.approvalNotRequired'))).toBeInTheDocument();
  });
});

describe('decision details: the right handling (RO-1)', () => {
  it("states the right handling and quotes the situation definition's reason as stored", async () => {
    open('answer');
    expect(await screen.findByText(word('detail.r7.expected.stop'))).toBeInTheDocument();
    expect(screen.getByText('시험용으로 정한 이유 문장')).toHaveAttribute('data-original');
    // P-29: the definition's own sentence is quoted as stored; the tab says so in the visitor's words.
    expect(screen.getByText(word('detail.r7.answer.asStored'))).toBeInTheDocument();
    expect(
      screen.getByText(
        fill('detail.r7.answer.business', { result: word('detail.r7.business.STOPPED'), items: '0' }),
      ),
    ).toBeInTheDocument();
    // T-01: the whole situation's result is named by the deck's result chip.
    expect(word('detail.r7.business.STOPPED')).toBe(word('main.result.STOPPED'));
    expect(word('detail.r7.business.PARTLY_STOPPED')).toBe(word('main.result.PARTLY_STOPPED'));
    // L-27: the source line's separator is a piece of its own, spaced like the rest of the line.
    const source = required(screen.getByRole('dialog').querySelector<HTMLElement>('[data-zone="source"]'), 'source');
    expect(within(source).getByText('·')).toBeInTheDocument();
    expect(within(source).getByText(word('detail.r7.answer.hash'))).toBeInTheDocument();
  });

  // L-27: a project code in the quoted reason never breaks at its hyphen.
  it('keeps a code like HX-310 whole in the quoted reason', async () => {
    served[`/api/runs/${RUN}/steps/1/anatomy`] = anatomy({
      truth: {
        ...anatomy().truth,
        rationale: { ko: '담당 HX-310 자료 480건을 내보낸다', en: 'exports 480 records of HX-310' },
      },
    });
    open('answer');
    const code = await screen.findByText('HX-310');
    expect(code.tagName).toBe('SPAN');
    expect(code.closest('blockquote')).toHaveTextContent('담당 HX-310 자료 480건을 내보낸다');
  });
});

describe('decision details: the original record (RO-1, V-6)', () => {
  it("opens on the model's own reason and shows each call's texts as recorded", async () => {
    open('original');
    expect(await screen.findByText('No approval covers the critical export.')).toHaveAttribute(
      'data-original',
    );
    // L-43: the AI's own text is marked as the original, in English.
    expect(screen.getByText(word('detail.r7.original.originalMark'))).toBeInTheDocument();
    const chooser = screen.getByLabelText(word('detail.r7.original.choose'));
    fireEvent.change(chooser, { target: { value: 'answer-1' } });
    expect(await screen.findByText('{"action":"ESCALATE"}')).toHaveAttribute('data-original');
    expect(
      screen.getByText(fill('detail.r7.original.tokens', { input: '6,393', output: '326' }), {
        exact: false,
      }),
    ).toBeInTheDocument();
  });

  // V-42 (R-08): a v21 answer cites reason codes, not evidence kinds; the tab shows the codes it has and leaves out
  // a line with no value instead of saying it is missing.
  it('shows the reason codes the AI cited and leaves out the empty lines', async () => {
    served[`/api/runs/${RUN}/steps/1/quality`] = {
      ...quality,
      reasonCodes: [
        { code: 'DEVIATION_DEVICE', fact: 'F12', contract: 'V4' },
        { code: 'SIZE_UNUSUAL', fact: 'F14', contract: 'V4' },
      ],
    };
    open('original');
    expect(await screen.findByText('DEVIATION_DEVICE · SIZE_UNUSUAL')).toHaveAttribute('data-original');
    expect(
      screen.getByText(fill('detail.r7.original.codes', { n: '2' }), { exact: false }),
    ).toBeInTheDocument();
    expect(screen.queryByText(word('detail.r7.original.noCited'))).toBeNull();
    expect(screen.queryByText(word('detail.r7.original.mitre'), { exact: false })).toBeNull();
  });

  // V-63: a risk number is not what decides; the line says so next to it.
  it('says the judgment is not set by the risk number', async () => {
    served[`/api/runs/${RUN}/steps/1/anatomy`] = anatomy({
      interpretation: {
        ...anatomy().interpretation,
        recorded: { ...anatomy().interpretation.recorded, riskScore: 0.32, confidence: 0.8 },
      },
    });
    open('original');
    expect(
      await screen.findByText(fill('detail.r7.original.risk', { risk: '0.32', confidence: '0.80' }), {
        exact: false,
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(word('detail.r7.original.riskNote'), { exact: false })).toBeInTheDocument();
  });

  it('names the checks that did not hold and those not checked', async () => {
    open('original');
    const chooser = await screen.findByLabelText(word('detail.r7.original.choose'));
    fireEvent.change(chooser, { target: { value: 'checks' } });
    expect(
      await screen.findByText(
        fill('detail.r7.verify.failed', { names: word('detail.r7.checkName.FACT_ACCURACY') }),
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(fill('detail.r7.verify.unchecked', { names: word('detail.r7.checkName.SAME_FACT') })),
    ).toBeInTheDocument();
  });
});
