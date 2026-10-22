import type { MeasuredCase, MeasuredRange, MeasuredRun } from '../api/measured';

/**
 * Test-only shapes of the portal's answers the timing part reads (화면재편 4-0 to 4-4): a measured case
 * (/api/cases/{key}/measured), a step result's Contexa layer and a fetch stub answering by address. The values are the
 * tests' own; imported by tests only, so they never reach the production bundle.
 */
export function measuredRun(
  runId: string,
  values: { readonly exposedItems: number; readonly responseMs: number | null; readonly analysisMs: number | null },
): MeasuredRun {
  return {
    runId,
    startedAt: '2026-10-17T08:30:06Z',
    result: 'STOPPED',
    engineAction: 'ESCALATE',
    reissueOutcome: null,
    releaseMillis: null,
    ...values,
  };
}

interface CaseValues {
  readonly results: Readonly<Record<string, number>>;
  readonly allSame?: boolean;
  readonly exposedItems?: MeasuredRange | null;
  readonly responseMs?: MeasuredRange | null;
  readonly analysisMs?: MeasuredRange | null;
  readonly list?: readonly MeasuredRun[];
  readonly middleRun?: string | null;
}

/** A measured case as the server counted it; the ranges are given, never worked out from the runs. */
export function measuredCase(caseKey: string, values: CaseValues): MeasuredCase {
  return {
    caseKey,
    settingHash: 'setting-test',
    protocolId: 'protocol-test',
    runs: 5,
    results: values.results,
    allSame: values.allSame ?? Object.keys(values.results).length === 1,
    resumed: null,
    exposedItems: values.exposedItems ?? null,
    responseMs: values.responseMs ?? null,
    analysisMs: values.analysisMs ?? null,
    list: values.list ?? [],
    middleRun: values.middleRun ?? null,
  };
}

/** A stored step result with Contexa's layer only (the timing screens read nothing else of it). */
export function contexaResult(values: {
  readonly outcome: string;
  readonly verdict: string | null;
  readonly timing: string | null;
  readonly deliveredItems: number;
  readonly responseMs: number | null;
}) {
  return {
    companyTime: '2026-09-30T03:17:00Z',
    layers: [
      {
        control: 'D',
        outcome: values.outcome,
        verdict: values.verdict,
        httpStatus: 200,
        ruleId: null,
        reason: null,
        ruleFacts: {},
        evidence: {
          decisionId: null,
          verdict: values.verdict,
          timing: values.timing,
          httpStatus: 200,
          outcome: values.outcome,
          deliveredItems: values.deliveredItems,
          engineReasoning: null,
          riskScore: null,
          confidence: null,
          unresolved: false,
          responseMs: values.responseMs,
          timeline: [],
          stream: null,
        },
      },
    ],
    engineReason: null,
    companyFacts: [],
    tally: {},
    existingTally: {},
  };
}

/** A stored decision record with only the analysis time the timing screens read. */
export function analysisRecord(totalAnalysisMs: number | null) {
  return { interpretation: { timings: { totalAnalysisMs } } };
}

/**
 * A fetch stub answering GET and POST by address from the given bodies, 404 for any other address. The visitor and
 * the journey are answered unless the bodies give their own.
 */
export function portalStub(bodies: () => Readonly<Record<string, unknown>>) {
  return (url: string) => {
    const all: Record<string, unknown> = {
      '/api/visitor': { predictions: {} },
      '/api/journey': { state: { route: 'DEFAULT', act: 4, step: 'sync-concept', differences: [] }, runs: [], predictions: [] },
      ...bodies(),
    };
    const body = all[url];
    return Promise.resolve(
      new Response(body === undefined || body === null ? null : JSON.stringify(body), { status: body ? 200 : 404 }),
    );
  };
}
