import { skipToken, useQueries, useQuery } from '@tanstack/react-query';
import { getJson } from './http';

/**
 * The verdict anatomy of one stored run step (docs/showcase/데모-재설계.md 3, portal DecisionAnatomy) and the model call
 * texts behind it. Only the parts the screens show are typed; every value is the stored record as the portal returns it.
 */
export interface UsualVsNow {
  readonly dimension: string;
  readonly now: string | null;
  /** The engine's own membership label: "true", "false" or an UNKNOWN sentence. */
  readonly inUsual: string | null;
  readonly labels: readonly string[];
}

export interface AdverseLabel {
  readonly label: string;
  readonly condition: string;
  readonly values: readonly string[];
  readonly met: boolean;
}

export interface AnatomyCall {
  readonly callNo: number;
  readonly model: string | null;
  readonly requestOptions: Readonly<Record<string, unknown>> | null;
  readonly finishReason: string | null;
  readonly promptTokens: number | null;
  readonly completionTokens: number | null;
  readonly reasoningTokens: number | null;
  readonly elapsedMs: number | null;
  readonly success: boolean;
  readonly failure: string | null;
  readonly answer: string | null;
  readonly parsedAnswer: Readonly<Record<string, unknown>> | null;
}

export interface AnatomyEvent {
  readonly type: string;
  readonly layer: string | null;
  readonly action: string | null;
  readonly elapsedMs: number | null;
  readonly observedAt: string | null;
  readonly reasoning: string | null;
  readonly riskScore: number | null;
  readonly confidence: number | null;
}

export interface TimelineEntry {
  readonly at: string;
  readonly kind: string;
  readonly name: string;
  readonly callNo: number | null;
  readonly detail: string | null;
}

/** The stored additional check of a step (run_challenge), as the portal returns the row. */
export interface StoredCheck {
  readonly answered: boolean;
  readonly reason: string | null;
  readonly reissue_outcome: string | null;
  readonly reissue_delivered: number | null;
  readonly reissue_elapsed_ms: number | null;
}

export interface DecisionAnatomyView {
  readonly builderVersion: number;
  readonly runId: string;
  readonly stepNo: number;
  readonly requestId: string;
  readonly operation: string;
  /** The step's additional check and block release as stored; null when the step had neither. */
  readonly recovery: { readonly challenge: StoredCheck | null; readonly release: unknown } | null;
  readonly context: {
    readonly usualVsNow: readonly UsualVsNow[];
    readonly usual: Readonly<{
      summary?: string | null;
      normalAccessHours?: readonly number[] | null;
      normalAccessDays?: readonly number[] | null;
    }> | null;
    readonly labelMatrix: Readonly<Record<string, string>>;
    readonly request: Readonly<Record<string, string | null>> | null;
    readonly learning: Readonly<{
      personalBaselineEstablished?: string | null;
      carryMissingFacts?: readonly string[] | null;
    }> | null;
    readonly resource: Readonly<{ sensitivity?: string | null; businessLabel?: string | null }> | null;
    readonly company: Readonly<{
      approvalLineage?: readonly string[] | null;
      approvalRequired?: boolean | null;
      approvalMissing?: boolean | null;
      approvalStatus?: string | null;
      approvalDecisionAgeMinutes?: number | null;
    }> | null;
    readonly coverage: Readonly<{ missingCriticalFacts?: readonly string[] | null }> | null;
    readonly rag: Readonly<{
      ragRetrievalState?: string | null;
      ragRelevance?: string | null;
      ragAuthorizedDocumentCount?: number | null;
    }> | null;
    readonly template: Readonly<{
      template_id?: string;
      allowed?: number;
      requests?: number;
      identity_checks?: number;
    }> | null;
  };
  readonly interpretation: {
    readonly calls: readonly AnatomyCall[];
    readonly recorded: {
      readonly proposedAction: string | null;
      readonly finalAction: string | null;
      readonly riskScore: number | null;
      readonly confidence: number | null;
      readonly reasoning: string | null;
      /** The code of the engine contract's fixed sentence when the reasoning is exactly that sentence; null otherwise. */
      readonly reasoningCode: string | null;
      readonly mitre: string | null;
      readonly unresolved: boolean;
      readonly failureType: string | null;
      readonly fallbackCategory: string | null;
      readonly applied: string | null;
      /** The kinds of evidence the model cited, as recorded. */
      readonly evidenceRefs: readonly string[] | null;
    };
    readonly modelReasoning: string | null;
    readonly reasoningDiffers: boolean;
    readonly contractLines: readonly string[];
    readonly timings: {
      readonly promptBuildMs: number | null;
      readonly ragVectorMs: number | null;
      readonly llmLatencyMs: number | null;
      readonly totalAnalysisMs: number | null;
      readonly events: readonly AnatomyEvent[];
    };
    readonly timeline: readonly TimelineEntry[];
    /** How long after the timeline's first entry each entry came, in the timeline's order, worked out on the server. */
    readonly sinceStartMs: readonly (number | null)[];
    /** The decision's prompt and completion tokens over every model call, summed on the server. */
    readonly promptTokens: number;
    readonly completionTokens: number;
  };
  readonly truth: {
    readonly classification: string | null;
    readonly allowedEngineActions: readonly string[];
    readonly rationale: Readonly<Record<string, string>> | null;
    readonly counterpoint: Readonly<Record<string, string>> | null;
    readonly truthSource: string | null;
    readonly verdict: {
      readonly score: {
        readonly result: string;
        readonly finalAction: string | null;
        readonly applicable: boolean;
        /** When the decision applied: BEFORE_RESPONSE, NEXT_REQUEST or NONE. */
        readonly applied: string | null;
      };
      readonly source: string;
      readonly proposedAction: string | null;
    } | null;
    readonly business: {
      readonly result: string;
      readonly exposedItems: number;
      readonly worstStep: number | null;
    } | null;
    readonly businessCorrect: boolean | null;
    readonly scenarioSha256: string | null;
  };
  /** What the engine learned during the run, read when the run ended; null when it was not captured. */
  readonly learning: {
    readonly atRunEnd: Readonly<Record<string, number>> | null;
    readonly template: Readonly<Record<string, number>> | null;
    readonly newBehaviourDocuments: readonly {
      readonly action: string | null;
      readonly requestPath: string | null;
      readonly timestamp: string | null;
      readonly riskScore: number | null;
      readonly userAgentBrowser: string | null;
      readonly userAgentOS: string | null;
    }[];
  } | null;
  readonly juxtaposition: {
    readonly departures: readonly UsualVsNow[];
    readonly companyFacts: readonly string[];
    readonly sensitivity: string | null;
    readonly modelReasoning: string | null;
    readonly recordedReasoning: string | null;
    readonly coreAdverseLabels: readonly AdverseLabel[];
    /** How many of the inspector's adverse conditions the prompt met, and how many it checks, counted by the server. */
    readonly adverseMet: number;
    readonly adverseChecked: number;
  };
  /**
   * Content lines of the prompt the engine sent, counted by the server (D-38): the seven bundles add up to the total.
   * Null when no text of the step was kept.
   */
  readonly promptLines: {
    readonly total: number;
    readonly system: number;
    readonly user: number;
    /** Every line as the opened raw text shows it; the line numbers a screen cites count these. */
    readonly systemPhysical: number;
    readonly userPhysical: number;
    readonly sections: readonly { readonly name: string; readonly bundle: string; readonly lines: number }[];
    /** In the screen's order. */
    readonly bundles: readonly {
      readonly bundle:
        'RULES' | 'REQUEST' | 'IDENTITY' | 'USUAL' | 'HISTORY' | 'COMPANY' | 'UNKNOWN' | 'OTHER';
      readonly lines: number;
    }[];
  } | null;
  /** Numbers the screens show, read or worked out from the record on the server. */
  readonly figures: {
    readonly workProfileWindow: string | null;
    readonly workProfileObservations: number | null;
    readonly baselineBefore: number | null;
    readonly baselineAfter: number | null;
    readonly baselineAdded: number | null;
    readonly documentsBefore: number | null;
    readonly documentsAfter: number | null;
    readonly documentsForThisRequest: number;
    /** How many compared items the engine rendered as not in the baseline; null when the request was not compared. */
    readonly departureCount: number | null;
  };
}

export interface ExchangeCall {
  readonly callNo: number;
  readonly model: string | null;
  readonly systemPrompt: string | null;
  readonly userPrompt: string | null;
  readonly answer: string | null;
  readonly finishReason: string | null;
  /** The model provider's HTTP response body as captured, session identifiers masked. */
  readonly providerResponse: string | null;
  readonly maskedPlaces: number;
  readonly capturedAt: string | null;
}

export interface ExchangesView {
  readonly runId: string;
  readonly stepNo: number;
  readonly kept: boolean;
  /** Why no text is stored, when not kept: deleted after the retention period, or never captured. */
  readonly missing: 'PAST_RETENTION' | 'NOT_COLLECTED' | null;
  readonly calls: readonly ExchangeCall[];
}

export interface CaseView {
  readonly key: string;
  readonly version: number;
  readonly title: Readonly<Record<string, string>>;
  readonly protagonist: string;
  readonly classification: string;
  readonly steps: number;
  readonly frozenOn: string | null;
  readonly sha256: string;
  /** The engine actions the case counts as right. */
  readonly allowedActions: readonly string[];
  readonly rationale: Readonly<Record<string, string>>;
  readonly counterpoint: Readonly<Record<string, string>>;
}

export interface CasesView {
  readonly canonicalForm: string;
  readonly rules: { readonly sha256: string | null; readonly covers: readonly string[] };
  readonly cases: readonly CaseView[];
  /** How many cases each ground truth classification has, counted by the server. */
  readonly classifications: Readonly<Record<string, number>>;
}

/** One engine input that differed between two runs of the same request, compared on the server. */
export interface InputChange {
  readonly key: string;
  readonly before: string | null;
  readonly now: string | null;
}

export function useInputChanges(runId: string | null, against: string | null, stepNo: number) {
  return useQuery({
    queryKey: ['input-changes', runId, against, stepNo],
    queryFn:
      runId && against
        ? () =>
            getJson<readonly InputChange[]>(
              `/api/runs/${encodeURIComponent(runId)}/steps/${stepNo}/input-changes?against=${encodeURIComponent(against)}`,
            )
        : skipToken,
    staleTime: Infinity,
    retry: false,
  });
}

/**
 * What the engine received in the latest real run of the same definition from the same current template (portal
 * BeforeSend), shown before the visitor sends. Every value is that run's anatomy; the run ID names the source.
 */
export interface BeforeSendView {
  readonly runId: string;
  readonly stepNo: number;
  readonly startedAt: string | null;
  readonly companyTime: string | null;
  readonly usualVsNow: readonly UsualVsNow[];
  /** What the baseline held for each dimension, copied from the prompt line the engine received; by dimension. */
  readonly usual: Readonly<Record<string, { readonly label: string; readonly values: readonly string[] }>>;
  readonly departures: readonly UsualVsNow[];
  /** How many dimensions departed from the baseline, counted by the portal. */
  readonly departureCount: number;
  /** The company record labels the core's response inspector read as adverse in that run. */
  readonly companyAdverse: readonly AdverseLabel[];
  /** How many they are, counted by the portal (the screen's "flagged by company records"). */
  readonly companyAdverseCount: number;
  /** The company records the business database returned (the engine's frictionProfile). */
  readonly company: Readonly<Record<string, unknown>>;
  readonly companyFacts: readonly string[];
  /** The same step's company facts as the business lookup returned them (the run's stored step result). */
  readonly businessFacts: readonly { readonly code: string; readonly value: string | null }[];
  readonly sensitivity: string | null;
  /**
   * The judgment rules' elevated-risk boundary in the engine's input (sensitivity HIGH or CRITICAL, an established
   * baseline, a departing label, ApprovalMissing=true), read by the portal; `applies` is null when one is unknown.
   */
  readonly boundary: {
    readonly sensitive: boolean;
    readonly established: boolean | null;
    readonly departs: boolean;
    readonly approvalMissing: boolean;
    readonly applies: boolean | null;
  };
}

/** `comparison` is null when no run of the same definition and template exists yet. */
export interface BeforeSend {
  readonly comparison: BeforeSendView | null;
}

const STORED = { staleTime: Infinity, retry: false } as const;

/** The comparison before sending a live case's request; 404 for a case the live runs do not offer. */
/** The before-sending query of a case's step, shared by the screens and by the first-load prefetch (screens.tsx). */
export function beforeSendQuery(scenario: string | null, stepNo: number) {
  return {
    queryKey: ['before', scenario, stepNo],
    queryFn: scenario
      ? () => getJson<BeforeSend>(`/api/live/before/${encodeURIComponent(scenario)}?step=${stepNo}`)
      : skipToken,
    staleTime: 60_000,
    retry: false,
  } as const;
}

export function useBeforeSend(scenario: string | null, stepNo: number) {
  return useQuery(beforeSendQuery(scenario, stepNo));
}

/** The anatomy of a stored step never changes, so it is read once. */
export function useAnatomy(runId: string | null, stepNo: number) {
  return useQuery({
    queryKey: ['anatomy', runId, stepNo],
    queryFn: runId
      ? () => getJson<DecisionAnatomyView>(`/api/runs/${encodeURIComponent(runId)}/steps/${stepNo}/anatomy`)
      : skipToken,
    ...STORED,
  });
}

/** The anatomies of the first `steps` steps of a stored run, in step order; empty before the run is known. */
export function useAnatomies(runId: string | null, steps: number) {
  return useQueries({
    queries: Array.from({ length: runId ? steps : 0 }, (_, index) => ({
      queryKey: ['anatomy', runId, index + 1],
      queryFn: () =>
        getJson<DecisionAnatomyView>(
          `/api/runs/${encodeURIComponent(runId ?? '')}/steps/${index + 1}/anatomy`,
        ),
      ...STORED,
    })),
  });
}

/**
 * What the engine received in one stored step, as the same view as the comparison before sending (the decision
 * details' "received" tab, 7.7).
 */
export function useReceived(runId: string | null, stepNo: number) {
  return useQuery({
    queryKey: ['received', runId, stepNo],
    queryFn: runId
      ? () => getJson<BeforeSendView>(`/api/runs/${encodeURIComponent(runId)}/steps/${stepNo}/received`)
      : skipToken,
    ...STORED,
  });
}

/** The model call texts are read only when the visitor opens them (second click, 3). */
export function useExchanges(runId: string | null, stepNo: number, open: boolean) {
  return useQuery({
    queryKey: ['exchanges', runId, stepNo],
    queryFn:
      runId && open
        ? () => getJson<ExchangesView>(`/api/runs/${encodeURIComponent(runId)}/steps/${stepNo}/exchanges`)
        : skipToken,
    ...STORED,
  });
}

export function useCases() {
  return useQuery({
    queryKey: ['cases'],
    queryFn: () => getJson<CasesView>('/api/cases'),
    staleTime: 60_000,
  });
}
