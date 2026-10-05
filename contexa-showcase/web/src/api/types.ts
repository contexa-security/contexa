import type { BusinessOutcome, ControlId, Verdict } from '../domain/verdict';

/** Shapes of the portal's visitor API (showcase-portal ReplayView). Every value comes from stored real runs. */
export type Localized = Readonly<Record<'ko' | 'en', string>>;

export interface PairSummary {
  readonly key: string;
  readonly order: number;
  readonly question: Localized;
  readonly recorded: boolean;
}

export type Timing =
  'BEFORE_RESPONSE' | 'MID_RESPONSE' | 'NEXT_REQUEST' | 'NONE' | 'STATIC_AUTHORIZATION' | 'NOT_ANALYSED';

export interface Evidence {
  readonly decisionId: string | null;
  readonly verdict: Verdict;
  readonly timing: Timing;
  readonly httpStatus: number | null;
  readonly outcome: BusinessOutcome;
  readonly deliveredItems: number;
  readonly engineReasoning: string | null;
  readonly riskScore: number | null;
  readonly confidence: number | null;
  readonly unresolved: boolean;
  /** Milliseconds from sending the request to receiving the response. */
  readonly responseMs: number | null;
  /** Engine events of this step, timed from the moment the request was sent (P3-BE-03). */
  readonly timeline: readonly TimelineEvent[];
  /** How far a streamed export got; null for other operations. */
  readonly stream: StreamProgress | null;
}

/** [milliseconds since the request was sent, delivered items]. */
export type StreamSample = readonly [number, number];

export interface StreamProgress {
  readonly total: number | null;
  readonly delivered: number;
  readonly firstLineMs: number | null;
  readonly endMs: number;
  /** True only when the engine wrote its in-band block marker. */
  readonly cut: boolean;
  /** The stream broke or ended short without the engine's marker. */
  readonly interrupted: boolean;
  readonly samples: readonly StreamSample[];
}

export interface TimelineEvent {
  readonly type: string;
  readonly layer: string | null;
  readonly action: string | null;
  readonly atMs: number;
  readonly elapsedMs: number | null;
}

export type LiveStatus = 'QUEUED' | 'STARTING' | 'RUNNING' | 'CHALLENGE' | 'COMPLETED' | 'FAILED' | 'EXPIRED';

export type LiveStage = 'WAITING' | 'CODE_SHOWN' | 'CANCELLED' | 'VERIFYING' | 'DONE' | 'EXPIRED' | 'FAILED';

export interface LiveLayer {
  readonly outcome: BusinessOutcome;
  readonly httpStatus: number | null;
}

export interface LiveStep {
  readonly stepNo: number;
  readonly operation: string;
  readonly layers: Readonly<Partial<Record<ControlId, LiveLayer>>>;
}

/** Control D's additional check in a live run; times are milliseconds from the moment the check came back. */
export interface LiveChallenge {
  readonly stage: LiveStage;
  /** The code in the demo inbox, present only while it can be entered. */
  readonly code: string | null;
  readonly secondsLeft: number;
  readonly attempts: number;
  readonly error: string | null;
  readonly cause: string | null;
  readonly codeRequestedMs: number | null;
  readonly verifiedMs: number | null;
  readonly reissueSentMs: number | null;
  /** When the re-issued request's response came back. */
  readonly reissueDoneMs: number | null;
  readonly reissueStatus: number | null;
  readonly reissueOutcome: BusinessOutcome | null;
}

export interface LiveRunView {
  readonly liveRunId: string;
  readonly scenario: string;
  readonly status: LiveStatus;
  /** Place in the queue while QUEUED, 0 otherwise. */
  readonly queuePosition: number;
  readonly runId: string | null;
  /** Milliseconds from the request to the visitor's space being ready. */
  readonly readyMs: number | null;
  readonly readyStages?: Readonly<Record<string, number>>;
  readonly steps: readonly LiveStep[];
  readonly challenge: LiveChallenge | null;
  readonly failure: string | null;
}

export interface LiveScenario {
  readonly key: string;
  readonly title: Localized;
  readonly classification: string;
}

export interface LiveConfig {
  readonly scenarios: readonly LiveScenario[];
  /** Present only when the human check is on. */
  readonly turnstileSiteKey: string | null;
  readonly dailyRuns: number;
  readonly remainingToday: number;
  /** Live runs are pausing: today's allotment is spent or every space and the queue are full. */
  readonly paused: boolean;
}

export type Slot = 'DAWN' | 'MORNING' | 'AFTERNOON' | 'EVENING';

export type TicketState = 'NONE' | 'MISMATCH' | 'MATCH';

export type DeviceState = 'USUAL' | 'NEW';

export interface CombinationCell {
  readonly key: string;
  readonly slot: Slot;
  readonly items: number;
  readonly recorded: boolean;
  readonly recordedAt: string | null;
  readonly engineVerdict: Verdict | null;
  readonly engineOutcome: BusinessOutcome | null;
}

export interface CombinationGrid {
  readonly catalogVersion: number;
  readonly employees: readonly string[];
  readonly items: readonly number[];
  readonly cells: readonly CombinationCell[];
}

export interface StepResult {
  readonly companyTime: string;
  readonly layers: readonly Layer[];
  readonly engineReason: EngineReason | null;
  readonly companyFacts: readonly Fact[];
}

export interface CombinationView {
  readonly key: string;
  readonly employee: string;
  readonly slot: Slot;
  readonly items: number;
  readonly ticket: TicketState;
  readonly device: DeviceState;
  readonly recorded: boolean;
  readonly recordedAt: string | null;
  readonly runId: string | null;
  readonly result: StepResult | null;
}

export interface Layer {
  readonly control: ControlId;
  readonly outcome: BusinessOutcome;
  readonly verdict: Verdict;
  readonly httpStatus: number | null;
  readonly ruleId: string | null;
  readonly reason: string | null;
  readonly ruleFacts: Readonly<Record<string, unknown>>;
  readonly evidence: Evidence;
}

export interface EngineReason {
  readonly canonical: string | null;
  readonly reasoning: string | null;
  readonly evidenceRefs: readonly string[];
  readonly deltas: readonly string[];
  readonly resourceSensitivity: string | null;
}

export interface Fact {
  readonly code: string;
  readonly value: string | null;
}

export type SceneKind = 'ATTACK' | 'LEGITIMATE';

export interface Scene {
  readonly kind: SceneKind;
  readonly sentence: Localized;
  readonly recordId: string;
  readonly agreeing: number;
  readonly repetitions: number;
  readonly recordedAt: string;
  readonly specHash: string;
  readonly companyTime: string;
  readonly featuredStep: number;
  readonly steps: number;
  readonly layers: readonly Layer[];
  readonly engineReason: EngineReason | null;
  readonly companyFacts: readonly Fact[];
}

export interface Pair {
  readonly key: string;
  readonly question: Localized;
  readonly scenes: readonly Scene[];
}

export interface ExecutionSpec {
  readonly specHash: string;
  readonly spec: {
    readonly codeCommit: string;
    readonly engineVersion: string;
    readonly effectiveMode: string;
    readonly chatModel: string;
    readonly embeddingModel: string;
    readonly embeddingDimensions: number;
    readonly promptHash: string;
    readonly templateId: string | null;
    readonly ruleVersion: string;
    readonly contractVersion: string | null;
    readonly timeZone: string;
  };
}

export type Choice = 'ALLOW' | 'BLOCK';

export interface VisitorState {
  readonly predictions: Readonly<Record<string, Choice>>;
}

export interface PredictionResult {
  readonly scene: string;
  readonly choice: Choice;
  readonly recorded: boolean;
  readonly tally: Readonly<Record<Choice, number>>;
}

/** Execution statistics (deck p.17): an operations record counted from the stored real runs. */
export interface StatsView {
  readonly computedAt: string;
  readonly runs: {
    readonly completed: number;
    readonly failed: number;
    readonly today: number;
    readonly live: number;
    readonly firstAt: string | null;
    readonly lastAt: string | null;
  };
  readonly decisionTime: {
    readonly decisions: number;
    readonly p50Ms: number | null;
    readonly p95Ms: number | null;
  };
  readonly engineActions: Readonly<Record<'ALLOW' | 'CHALLENGE' | 'BLOCK' | 'ESCALATE', number>>;
  readonly unresolved: { readonly technical: number; readonly noNewAnalysis: number };
  readonly agreement: {
    readonly agreeing: number;
    readonly repetitions: number;
    readonly recordings: readonly {
      readonly pairKey: string;
      readonly scene: string;
      readonly agreeing: number;
      readonly repetitions: number;
      readonly recordedAt: string;
    }[];
  };
  readonly scope: { readonly threatRuns: number; readonly normalRuns: number; readonly otherRuns: number };
  readonly layers: readonly {
    readonly control: ControlId;
    readonly threat: {
      readonly runs: number;
      readonly leaked: number;
      readonly stopped: number;
      readonly unresolved: number;
    };
    readonly normal: {
      readonly runs: number;
      readonly passed: number;
      readonly challenged: number;
      readonly blocked: number;
      readonly unresolved: number;
    };
  }[];
  readonly spec: {
    readonly specHash: string;
    readonly codeCommit: string;
    readonly engineVersion: string;
    readonly effectiveMode: string;
    readonly chatModel: string;
    readonly embeddingModel: string;
    readonly timeZone: string;
  } | null;
  readonly specCount: number;
}
