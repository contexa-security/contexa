import type { AdverseLabel } from './anatomy';
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
  | 'BEFORE_RESPONSE'
  | 'MID_RESPONSE'
  | 'NEXT_REQUEST'
  | 'NONE'
  | 'PRIOR_DECISION'
  | 'STATIC_AUTHORIZATION'
  | 'NOT_ANALYSED';

export interface Evidence {
  readonly decisionId: string | null;
  /** The engine's decision; null for a rule control, which makes none (H-08b). */
  readonly verdict: Verdict | null;
  /** When the engine's decision applied; null for a rule control. */
  readonly timing: Timing | null;
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
  /** The engine's model calls for this request, as measured at the model boundary. */
  readonly modelCalls?: readonly ModelCall[];
}

export interface ModelCall {
  readonly model: string | null;
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly totalTokens: number;
  readonly elapsedMs: number | null;
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

/** AWAITING: the run waits for the visitor to send its next step (the attacker trying again). */
export type LiveStatus =
  | 'QUEUED'
  | 'STARTING'
  | 'RUNNING'
  | 'CHALLENGE'
  | 'AWAITING'
  | 'BLOCKED'
  | 'COMPLETED'
  | 'FAILED'
  | 'EXPIRED';

export type LiveStage =
  | 'WAITING'
  | 'CODE_SHOWN'
  | 'CANCELLED'
  | 'VERIFYING'
  | 'DONE'
  | 'EXPIRED'
  | 'FAILED'
  | 'ABANDONED'
  | 'NO_MAILBOX';

/** The release of a block (ADR-33), from the block to the request going out again after the approval. */
export type LiveReleaseStage =
  | 'BLOCKED'
  | 'CODE_SHOWN'
  | 'VERIFIED'
  | 'REQUESTED'
  | 'APPROVING'
  | 'DONE'
  | 'NO_MAILBOX'
  | 'EXPIRED'
  | 'FAILED'
  | 'ABANDONED';

/** The engine's record of the block as its administrator API returns it. */
export interface LiveBlockRecord {
  readonly id: number;
  /** The account the engine recorded the block on. */
  readonly username: string | null;
  readonly status: string | null;
  /** Why the engine blocked the account, as the engine wrote it. */
  readonly reasoning: string | null;
  readonly blockedAt: string | null;
  readonly unblockReason: string | null;
  readonly mfaVerified: boolean | null;
  readonly unblockRequestedAt: string | null;
}

/** Milliseconds are counted from the moment the block came back. */
export interface LiveRelease {
  readonly stage: LiveReleaseStage;
  readonly code: string | null;
  readonly secondsLeft: number;
  readonly attempts: number;
  readonly error: string | null;
  readonly cause: string | null;
  readonly reason: string | null;
  readonly block: LiveBlockRecord | null;
  /** The security administrator who reads the request, as the work database names them. */
  readonly approverName: string | null;
  readonly codeRequestedMs: number | null;
  readonly verifiedMs: number | null;
  readonly requestedMs: number | null;
  readonly approvedMs: number | null;
  readonly reissueSentMs: number | null;
  readonly reissueDoneMs: number | null;
  readonly reissueStatus: number | null;
  readonly reissueOutcome: BusinessOutcome | null;
  readonly reissueDeliveredItems: number | null;
}

export interface LiveLayer {
  readonly outcome: BusinessOutcome;
  readonly httpStatus: number | null;
  /** Items the control actually handed over in its response. */
  readonly deliveredItems: number;
  /** Milliseconds from sending the request to its response. */
  readonly elapsedMs: number;
  /**
   * The rule the control recorded for its answer; for Contexa, ACCOUNT_BLOCKED or MFA_CHALLENGE_REQUIRED when a decision
   * already in force refused the request. Null when none was recorded.
   */
  readonly ruleId?: string | null;
}

/** How far a control's streamed export got while it is still being read. */
export interface LiveStream {
  /** Items the export announced, null when the response did not say. */
  readonly total: number | null;
  readonly delivered: number;
  /** Milliseconds since the request was sent. */
  readonly atMs: number;
}

export interface LiveStep {
  readonly stepNo: number;
  /** Null while only stream progress has arrived for the step. */
  readonly operation: string | null;
  readonly layers: Readonly<Partial<Record<ControlId, LiveLayer>>>;
  readonly streams?: Readonly<Partial<Record<ControlId, LiveStream>>>;
}

/** One stage of the engine's analysis of the visitor's own run, timed from when control D received the request. */
export interface AnalysisStage {
  readonly type: string;
  readonly atMs: number | null;
  readonly action: string | null;
  readonly layer: string | null;
  readonly riskScore: number | null;
  readonly confidence: number | null;
  readonly elapsedMs: number | null;
  readonly mitre: string | null;
}

/**
 * Control D's decision of a step once the engine closed its analysis, before the run ends (portal LiveDecision).
 * Every value is the engine's own record.
 */
export interface LiveDecision {
  readonly finalAction: string;
  readonly proposedAction: string | null;
  readonly unresolved: boolean;
  readonly riskScore: number | null;
  readonly confidence: number | null;
  readonly applied: 'BEFORE_RESPONSE' | 'NEXT_REQUEST';
  readonly reason: EngineReason | null;
  /** The labels the core's response inspector reads as adverse evidence; empty when D no longer holds the call. */
  readonly adverseLabels: readonly AdverseLabel[];
  /** How many of them the prompt met, counted by the portal. */
  readonly adverseMet: number;
  /** How many adverse conditions the inspector checks, counted by the portal. */
  readonly adverseChecked: number;
  readonly totalAnalysisMs: number | null;
  readonly modelCalls: number;
  readonly promptTokens: number;
  readonly completionTokens: number;
}

export interface AnalysisView {
  readonly stepNo: number;
  readonly stages: readonly AnalysisStage[];
  /** Null until the engine closed the analysis, or when it made no decision record. */
  readonly decision: LiveDecision | null;
  /** While the decision is still coming: how long the same case and step took in the current measurement. */
  readonly decisionWait: DecisionWait | null;
}

/** The "about s seconds" of the decision-waiting state, counted by the portal from the measurement. */
export interface DecisionWait {
  /** The median analysis time of the engine's decisions of the same case and step in the measurement. */
  readonly medianMs: number;
  readonly decisions: number;
  readonly settingHash: string;
  readonly waitedMs: number;
  /** The median less the wait so far, rounded up; null once the wait passed the median. */
  readonly remainingSeconds: number | null;
}

/** What Contexa knows about an employee: the engine's learned baseline and the work that taught it. */
export interface BaselineCardView {
  readonly employeeKey: string;
  readonly displayName: string;
  readonly department: string;
  readonly templateId: string;
  /** When the template's snapshot of the engine's baseline was taken; null when the snapshot does not say. */
  readonly capturedAt?: string | null;
  readonly learned: {
    readonly requests: number;
    /** Learned requests per hour, index 0 to 23. */
    readonly hours: readonly number[];
    /** Learned requests per weekday, index 0 = Monday. */
    readonly weekdays: readonly number[];
    readonly networks: readonly string[];
    readonly devices: readonly string[];
  };
  readonly taught: {
    readonly reads: number;
    readonly downloads: number;
    readonly exports: number;
    readonly exportItemsMin: number | null;
    readonly exportItemsMax: number | null;
    readonly projects: Readonly<Record<string, number>>;
    readonly from: string | null;
    readonly to: string | null;
  };
  /** Every request sent to teach the template, in order, as the learner sent it and the engine answered it. */
  readonly requests: readonly LearnedRequest[];
  /** How many requests were sent to teach the template. */
  readonly sent: number;
  /** How many of them the engine allowed; the baseline learned `learned.requests`. */
  readonly allowed: number;
  /** The hour lists the engine received in the latest real decision made from the template; null before any. */
  readonly hours: EngineHours | null;
}

export interface LearnedRequest {
  /** The scripted activity number. */
  readonly no: number;
  readonly companyTime: string;
  readonly operation: string;
  readonly method: string;
  readonly path: string;
  /** The export size; null for any other operation. */
  readonly items: number | null;
  readonly clientAddress: string;
  readonly httpStatus: number | null;
  readonly finalAction: string | null;
  readonly unresolved: boolean | null;
  /** Whether the employee passed the engine's identity check; null without one. */
  readonly identityCheckPassed: boolean | null;
  readonly reissueOutcome: string | null;
}

/**
 * What the engine's prompt said about the learned behaviour in one real decision: the work profile's most frequent hours
 * (NormalAccessHours), every hour of the learned history (ObservedHours), which "in the usual hours" compares with, and
 * the state lines of each kind of learning, copied as written (null when a line is missing).
 */
export interface EngineHours {
  readonly normalAccessHours: readonly number[];
  readonly observedHours: readonly number[];
  readonly runId: string;
  readonly stepNo: number;
  readonly companyTime: string | null;
  /** PersonalBaselineStatus: ESTABLISHED once the personal baseline is learned enough. */
  readonly personalBaselineStatus: string | null;
  /** WorkProfileEvidenceState. */
  readonly workProfileState: string | null;
  /** RoleScopeEvidenceState: PROVISIONAL while the work scope is still being learned. */
  readonly roleScopeState: string | null;
  /** The engine's own sentence on the observed history (ObservedScopeSummary). */
  readonly observedScopeSummary: string | null;
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
  /** Items the re-issued request actually handed over. */
  readonly reissueDeliveredItems?: number | null;
}

export interface LiveRunView {
  readonly liveRunId: string;
  readonly scenario: string;
  readonly status: LiveStatus;
  /** Place in the queue while QUEUED, 0 otherwise. */
  readonly queuePosition: number;
  /** About how many seconds until the queued run starts, from the times of recent live runs; null otherwise. */
  readonly queueWaitSeconds: number | null;
  readonly runId: string | null;
  /** Milliseconds from the request to the visitor's space being ready. */
  readonly readyMs: number | null;
  readonly readyStages?: Readonly<Record<string, number>>;
  readonly steps: readonly LiveStep[];
  readonly challenge: LiveChallenge | null;
  readonly failure: string | null;
  /** The step the run waits for the visitor to send, null unless AWAITING. */
  readonly awaitingStep?: number | null;
  /** The release of a block, once control D blocked the account. */
  readonly release?: LiveRelease | null;
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

/** How many approaches stopped a request (STOPPED or CUT), let it through, or did neither; counted by the server. */
export interface Tally {
  readonly stopped: number;
  readonly passed: number;
  readonly other: number;
}

export interface StepResult {
  readonly companyTime: string;
  readonly layers: readonly Layer[];
  readonly engineReason: EngineReason | null;
  readonly companyFacts: readonly Fact[];
  /** Over the five approaches. */
  readonly tally: Tally;
  /** Over the four existing approaches, Contexa left out. */
  readonly existingTally: Tally;
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
  /** The engine's decision; null for a rule control, which states its rule and HTTP status instead (H-08b). */
  readonly verdict: Verdict | null;
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
  /** How many compared items the engine received as outside the baseline (CurrentVsObservedDeltaCount). */
  readonly baselineDeltaCount: number | null;
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
  /** The representative run of the scene, for its decision anatomy. */
  readonly runId: string;
  /** The ground truth of that run as recorded, shown whatever company facts the scene has (F-13). */
  readonly truth: SceneTruth;
}

export interface SceneTruth {
  readonly source: 'RUN_SNAPSHOT' | 'CATALOG_SAME_VERSION' | 'NONE';
  readonly classification: 'THREAT' | 'NORMAL' | 'UNCERTAIN' | null;
  readonly rationale: Readonly<Record<string, string>> | null;
  readonly counterpoint: Readonly<Record<string, string>> | null;
  /** The engine actions the truth counts as right. */
  readonly allowedActions: readonly string[];
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
  /** The engine's resolved decisions of every final action together, counted on the server. */
  readonly engineDecisions?: number;
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
    /** Business results over the whole case by the server's one scoring rule (docs/showcase/데모-재설계.md 5.0). */
    readonly threat: {
      readonly runs: number;
      readonly stopped: number;
      readonly partlyStopped: number;
      readonly missed: number;
      readonly unresolved: number;
      readonly exposedItems: number;
    };
    readonly normal: {
      readonly runs: number;
      readonly passed: number;
      readonly passedAfterCheck: number;
      readonly halted: number;
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
  /** Block releases recorded for the counted runs (forced runs left out). */
  readonly releases: number;
}

/** A control's business result over a whole case by the server's one scoring rule (docs/showcase/데모-재설계.md 5.0). */
export type CaseResult =
  | 'STOPPED'
  | 'PARTLY_STOPPED'
  | 'MISSED'
  | 'PASSED'
  | 'PASSED_AFTER_CHECK'
  | 'HALTED'
  | 'UNRESOLVED'
  | 'NOT_SCORED';

/** The score of a stored run (GET /api/runs/{runId}/score). */
export interface RunScore {
  readonly runId: string;
  readonly scenarioKey: string;
  readonly scenarioVersion: number;
  readonly status: string;
  readonly truthSource: 'RUN_SNAPSHOT' | 'CATALOG_SAME_VERSION' | 'NONE';
  readonly truth: {
    readonly classification: string | null;
    readonly allowedEngineActions: readonly string[];
  };
  readonly definedSteps: number | null;
  readonly executedSteps: number;
  readonly business: Readonly<
    Record<
      ControlId,
      { readonly result: CaseResult; readonly exposedItems: number; readonly worstStep: number | null }
    >
  >;
  /** Right or wrong for each control; a control left out is neither (a partial stop, unresolved, not scored). */
  readonly correct: Readonly<Partial<Record<ControlId, boolean>>>;
  /** How many approaches got the case right, counted by the server. */
  readonly rightControls: number;
  readonly verdicts: readonly {
    readonly score: {
      readonly stepNo: number;
      readonly finalAction: string | null;
      readonly result: 'RIGHT' | 'MISSED' | 'FALSE_BLOCK' | 'UNRESOLVED' | 'NO_DECISION' | 'NOT_SCORED';
      readonly applicable: boolean;
      readonly friction: boolean;
      /** When the decision applied. */
      readonly applied: 'BEFORE_RESPONSE' | 'NEXT_REQUEST' | 'NONE' | null;
    };
    readonly source:
      'MODEL' | 'PROPOSAL_CHANGED' | 'FALLBACK' | 'PRIOR_DECISION' | 'STATIC_AUTHORIZATION' | 'NOT_ANALYSED';
    readonly proposedAction: string | null;
    /** When the engine recorded its decision of the step; null without a decision record. */
    readonly decidedAt?: string | null;
  }[];
  readonly checks: readonly {
    readonly stepNo: number;
    readonly answered: boolean;
    readonly reissueOutcome: string | null;
    readonly releaseMillis: number | null;
  }[];
  /** The case's name by language as stored with the run (a changed lab case has its own), else the catalog's. */
  readonly title: Readonly<Record<string, string>> | null;
  /** When the run ended, as recorded; null while it runs. */
  readonly finishedAt?: string | null;
}

/** The visitor's result of a pair (deck p.15), scored on the server; the share card uses the same numbers. */
export interface ExperienceScore {
  readonly hits: number;
  readonly total: number;
}

export interface ExperienceResult {
  readonly pairKey: string;
  readonly scenes: readonly {
    readonly kind: 'ATTACK' | 'LEGITIMATE';
    readonly choice: Choice | null;
    /** The first question's call, carried over to this look-alike scene. */
    readonly carriedOver: boolean;
    readonly myCorrect: boolean | null;
    readonly contexaOutcome: BusinessOutcome;
    readonly contexaVerdict: Verdict;
    /** Control D's business result over the whole case, scored on the server. */
    readonly contexaResult: CaseResult;
    readonly contexaExposed: number;
    /** Null for a partial stop, an unresolved case or a case without a ground truth. */
    readonly contexaCorrect: boolean | null;
    /** The ground truth of the scene's run as recorded (F-13). */
    readonly truth: SceneTruth;
    /** The case the scene's run executed. */
    readonly scenarioKey: string;
    /** From the additional check to the work going through again, when the run recorded it; null otherwise. */
    readonly resumedMillis: number | null;
  }[];
  /** Null when the visitor watched without voting. */
  readonly mine: ExperienceScore | null;
  readonly contexa: ExperienceScore;
}

export interface ShareResponse {
  readonly shareKey: string;
  readonly url: string;
  readonly image: string;
}
