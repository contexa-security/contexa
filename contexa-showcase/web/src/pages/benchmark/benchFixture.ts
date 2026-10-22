import type {
  BenchmarkCase,
  BenchmarkConclusions,
  BenchmarkRate,
  BenchmarkView,
  ControlScore,
} from '../../api/benchmark';
import type { ControlId } from '../../domain/verdict';

/**
 * Test-only shapes of the portal's benchmark answer (/api/benchmark, BenchmarkView) and a fetch stub answering by
 * address. The values are the tests' own; imported by tests only, so they never reach the production bundle.
 */
export function rate(hits: number, total: number, preliminary = false, low = 0.5, high = 0.9): BenchmarkRate {
  return { hits, total, rate: total > 0 ? hits / total : null, low, high, preliminary };
}

interface ScoreValues {
  readonly stopped: readonly [number, number];
  readonly stoppedAny: readonly [number, number];
  readonly notBlocked: readonly [number, number];
  readonly falseBlock?: number;
  readonly friction?: number;
  readonly missed?: number;
  readonly partly?: number;
  readonly exposed?: number;
  readonly preliminary?: boolean;
}

export function score(control: ControlId, values: ScoreValues): ControlScore {
  const pre = values.preliminary ?? false;
  return {
    control,
    stopped: rate(values.stopped[0], values.stopped[1], pre),
    stoppedAny: rate(values.stoppedAny[0], values.stoppedAny[1], pre),
    stoppedMacro: null,
    stoppedAnyMacro: null,
    falseBlock: rate(values.falseBlock ?? 0, values.notBlocked[1]),
    friction: rate(values.friction ?? 0, values.notBlocked[1]),
    falseBlockMacro: null,
    attackUnresolved: 0,
    normalUnresolved: 0,
    exposedItems: values.exposed ?? 0,
    partlyStopped: values.partly ?? 0,
    missed: values.missed ?? 0,
    normalPassed: values.notBlocked[0],
    notBlocked: rate(values.notBlocked[0], values.notBlocked[1], pre),
  };
}

type Cells = Partial<Record<ControlId, readonly [number, number]>>;

export function benchCase(
  key: string,
  classification: 'THREAT' | 'NORMAL' | 'UNCERTAIN',
  cells: Cells,
  extra: Partial<BenchmarkCase> = {},
): BenchmarkCase {
  const entries = Object.entries(cells) as [ControlId, readonly [number, number]][];
  return {
    key,
    classification,
    title: { ko: `서버 제목 ${key}`, en: `Server title ${key}` },
    runs: 5,
    definitionSha256: [],
    results: {},
    engineActions: {},
    engineVerdicts: {},
    decisionSources: {},
    runIds: [`run-${key.toLowerCase()}aaaaaa1`, `run-${key.toLowerCase()}aaaaaa2`],
    risk: { min: null, max: null, scored: 0, decisions: 0 },
    cells: Object.fromEntries(
      entries.map(([control, [right, counted]]) => [
        control,
        { right, counted, state: right === counted ? 'RIGHT' : right === 0 ? 'WRONG' : 'MIXED' },
      ]),
    ),
    contexaWrong: false,
    missedEveryRun: false,
    ...extra,
  };
}

const ALL: Cells = { A: [0, 5], B: [0, 5], C1: [5, 5], C2: [5, 5], D: [5, 5] };

export function conclusions(values: Partial<BenchmarkConclusions> = {}): BenchmarkConclusions {
  return {
    mostStopped: { controls: ['D'], hits: 85, total: 85 },
    mostFalseBlock: { controls: ['C1'], hits: 40, total: 75 },
    cleanMostStopped: { controls: ['D'], hits: 85, total: 85 },
    ...values,
  };
}

const CONTROLS: readonly ControlScore[] = [
  score('A', { stopped: [5, 85], stoppedAny: [5, 85], notBlocked: [75, 75] }),
  score('B', { stopped: [5, 85], stoppedAny: [5, 85], notBlocked: [75, 75] }),
  score('C1', { stopped: [55, 85], stoppedAny: [60, 85], notBlocked: [35, 75], falseBlock: 40, missed: 25 }),
  score('C2', { stopped: [60, 85], stoppedAny: [65, 85], notBlocked: [75, 75] }),
  score('D', { stopped: [30, 85], stoppedAny: [85, 85], notBlocked: [75, 75], friction: 5, exposed: 50755 }),
];

/** A benchmark with twenty-one situations: eleven attacks, eight normal tasks, two open ones. */
export function benchmark(overrides: Partial<BenchmarkView> = {}): BenchmarkView {
  const spec = {
    settingHash: 'f'.repeat(64),
    chatModel: 'model-test',
    modelSettings: null,
    codeCommit: 'commit-test',
    engineVersion: '0.1.0',
    ruleVersion: 'r'.repeat(64),
    contractVersion: 'c'.repeat(64),
    templates: [],
    templateVersions: [],
    promptHashes: [],
    protocolRuns: 105,
    firstRunAt: '2026-10-17T08:29:14Z',
    lastRunAt: '2026-10-17T11:49:06Z',
  };
  const attacks = Array.from({ length: 11 }, (_, index) => benchCase(`T${index + 1}`, 'THREAT', ALL));
  const normal = Array.from({ length: 8 }, (_, index) => benchCase(`N${index + 1}`, 'NORMAL', ALL));
  const open = [benchCase('U1', 'UNCERTAIN', {}), benchCase('U2', 'UNCERTAIN', {})];
  return {
    computedAt: '2026-10-18T09:00:00Z',
    notices: ['METHODS_NOT_PRODUCTS', 'VISITORS_APART'],
    specs: [spec],
    spec,
    scope: {
      runs: 105,
      attackRuns: 55,
      normalRuns: 40,
      otherRuns: 10,
      cases: 21,
      protocols: [
        {
          protocolId: 'protocol-test',
          repeat: 5,
          cases: 21,
          plannedRuns: 105,
          startedAt: spec.firstRunAt,
          finishedAt: spec.lastRunAt,
          completedRuns: 105,
          failedRuns: 0,
          forcedRuns: 0,
        },
      ],
    },
    controls: CONTROLS,
    // Mixed order on purpose: the server's order is not grouped by kind.
    cases: [...normal.slice(0, 1), ...attacks, ...normal.slice(1), ...open],
    wrongRuns: [],
    wrongRunCount: 0,
    unresolvedRuns: 0,
    suites: [
      {
        suite: 'RULE_BLIND',
        cases: [],
        runs: 30,
        controls: CONTROLS,
        conclusions: conclusions({
          mostStopped: { controls: ['C2', 'D'], hits: 12, total: 15 },
        }),
      },
    ],
    riskJudged: { runs: 46, stopped: 44 },
    judgmentTiming: { STATIC_REFUSAL: 5, BEFORE_RESPONSE: 25, NEXT_REQUEST: 10, JUDGED_ALLOW: 3, OTHER: 0 },
    engine: {
      decisions: 120,
      actions: {},
      unresolved: 0,
      analysisP50Ms: 5900,
      analysisP95Ms: 9100,
      analysisMeasured: 120,
      costPerDecisionUsd: 0.0123,
      priceSource: 'price-test',
      promptTokens: 0,
      cachedTokens: 0,
      completionTokens: 0,
      tokensPerDecision: 3400,
      tokensMeasured: 120,
      modelCallsPerDecision: 1.5,
      modelCalls: 180,
    },
    observations: {
      liveRuns: 31,
      labRuns: 7,
      composedRuns: 2,
      predictionsAll: 20,
      predictions: rate(12, 18),
      unsurePredictions: 2,
      designedPredictions: 18,
      assessments: 4,
      assessors: 3,
      soundShareWeighted: null,
      verdicts: {},
      reasons: {},
      delayHours: 1,
    },
    protocolRunsWithoutSetting: 0,
    caseCounts: { THREAT: 11, NORMAL: 8, UNCERTAIN: 2 },
    contexaWrongCases: { THREAT: 0, NORMAL: 0, UNCERTAIN: 0 },
    conclusions: conclusions(),
    missedEveryRunCases: [],
    ...overrides,
  };
}

type Answer = { readonly status: number; readonly body: unknown };

/**
 * The answers of the portal by address (the query string aside); anything else is a 404. The answers are read at each
 * call, so a test that sets its answer after the stub is installed (in beforeEach) is answered with its own.
 */
export function stubFetch(answers: () => Readonly<Record<string, Answer>>) {
  const base: Record<string, Answer> = {
    '/api/visitor': { status: 200, body: { predictions: {} } },
    '/api/journey': {
      status: 200,
      body: { state: { route: 'DEFAULT', act: 0, step: null, differences: [] }, runs: [], predictions: [] },
    },
  };
  return async (url: string) => {
    const path = url.split('?')[0] ?? url;
    const { status, body } = answers()[path] ?? base[path] ?? { status: 404, body: null };
    return new Response(body === null ? null : JSON.stringify(body), { status });
  };
}
