import { useAnatomy, type DecisionAnatomyView } from '../../../api/anatomy';
import { useJourney } from '../../../api/journey';
import { useRunStepResults } from '../../../api/lab';
import { useLiveAnalysis, useLiveRun } from '../../../api/queries';
import type {
  AnalysisStage,
  DecisionWait,
  LiveDecision,
  LiveLayer,
  LiveRunView,
  StepResult,
} from '../../../api/types';
import { CONTROL_ORDER } from '../../../domain/verdict';

/**
 * The visitor's run of a try's case. While the run is the portal's current one it is the live view; once the portal
 * has restarted (it keeps the current run in memory only), the latest finished run of the case in the visitor's
 * journey (stored in the database) stands in, drawn from its stored step results, so a run the visitor already sent
 * never reads as "not sent yet" (15.3).
 */
export function useTryRun(caseKey: string, steps: number) {
  const live = useLiveRun(true);
  const current = live.data?.scenario === caseKey ? live.data : null;
  const journey = useJourney(current === null);
  const storedId = current
    ? null
    : ([...(journey.data?.runs ?? [])]
        .reverse()
        .find((line) => line.scenarioKey === caseKey && line.status === 'COMPLETED')?.runId ?? null);
  const results = useRunStepResults(storedId, steps);
  const stored =
    storedId !== null && results.length > 0 && results.every((result) => result !== undefined)
      ? storedView(caseKey, storedId, results as readonly StepResult[])
      : null;
  return {
    pending: live.isPending || (current === null && (journey.isPending || (storedId !== null && stored === null))),
    view: current ?? stored,
    /** The run is read from its stored records, not followed live. */
    stored: current === null && stored !== null,
    runId: current?.runId ?? storedId,
  };
}

/** A finished run as the live view draws it: every step's answers from the stored step results. */
function storedView(caseKey: string, runId: string, results: readonly StepResult[]): LiveRunView {
  return {
    liveRunId: `stored-${runId}`,
    scenario: caseKey,
    status: 'COMPLETED',
    queuePosition: 0,
    queueWaitSeconds: null,
    runId,
    readyMs: null,
    steps: results.map((result, index) => ({
      stepNo: index + 1,
      operation: null,
      layers: Object.fromEntries(
        CONTROL_ORDER.flatMap((control) => {
          const layer = result.layers.find((candidate) => candidate.control === control);
          if (!layer) {
            return [];
          }
          const live: LiveLayer = {
            outcome: layer.outcome,
            httpStatus: layer.httpStatus,
            deliveredItems: layer.evidence.deliveredItems,
            elapsedMs: layer.evidence.responseMs ?? 0,
            ruleId: layer.ruleId,
          };
          return [[control, live]];
        }),
      ),
    })),
    challenge: null,
    failure: null,
  };
}

export interface TryAnalysis {
  /** Control D's decision of the request; null while it has not come yet, or when the run has none. */
  readonly decision: LiveDecision | null;
  /** The engine's analysis events so far; null before the first. */
  readonly stages: readonly AnalysisStage[] | null;
  readonly wait: DecisionWait | null;
  /** The stored run was read and it has no decision of the engine. */
  readonly missing: boolean;
}

/**
 * Control D's analysis of a request: the live analysis while the run is current, else the same values read from the
 * request's stored anatomy (the engine's own record either way).
 */
export function useTryAnalysis(view: LiveRunView | null, stored: boolean, step = 1): TryAnalysis {
  const following =
    view !== null && !stored && view.status !== 'QUEUED' && view.status !== 'STARTING';
  const live = useLiveAnalysis(stored ? null : (view?.liveRunId ?? null), step, following).data ?? null;
  const anatomy = useAnatomy(stored ? (view?.runId ?? null) : null, step);
  if (!stored) {
    return {
      decision: live?.decision ?? null,
      stages: live?.stages ?? null,
      wait: live?.decisionWait ?? null,
      missing: false,
    };
  }
  const record = anatomy.data ?? null;
  const decision = record ? decisionOf(record) : null;
  return {
    decision,
    stages: record ? storedStages(record) : null,
    wait: null,
    missing: record !== null && decision === null,
  };
}

/** The stored check of a request as the follow-up names it: how it ended, from the run's recorded check. */
export function useStoredCheck(runId: string | null, stored: boolean): string | null {
  const anatomy = useAnatomy(stored ? runId : null, 1).data ?? null;
  const check = anatomy?.recovery?.challenge ?? null;
  if (!check) {
    return null;
  }
  return check.reason ?? (check.answered ? 'DONE' : 'other');
}

/** The engine's analysis events as the engine recorded them with the decision. */
function storedStages(anatomy: DecisionAnatomyView): readonly AnalysisStage[] {
  return anatomy.interpretation.timings.events.map((event) => ({
    type: event.type,
    atMs: null,
    action: event.action,
    layer: event.layer,
    riskScore: event.riskScore,
    confidence: event.confidence,
    elapsedMs: event.elapsedMs,
    mitre: null,
  }));
}

function decisionOf(anatomy: DecisionAnatomyView): LiveDecision | null {
  const interpretation = anatomy.interpretation;
  const recorded = interpretation.recorded;
  if (recorded.finalAction === null) {
    return null;
  }
  return {
    finalAction: recorded.finalAction,
    proposedAction: recorded.proposedAction,
    unresolved: recorded.unresolved,
    riskScore: recorded.riskScore,
    confidence: recorded.confidence,
    applied: recorded.applied === 'NEXT_REQUEST' ? 'NEXT_REQUEST' : 'BEFORE_RESPONSE',
    reason: {
      canonical: recorded.reasoningCode,
      reasoning: recorded.reasoning,
      evidenceRefs: recorded.evidenceRefs ?? [],
      deltas: anatomy.juxtaposition.departures.map((row) => row.dimension),
      baselineDeltaCount: anatomy.figures.departureCount,
      resourceSensitivity: anatomy.juxtaposition.sensitivity,
    },
    adverseLabels: anatomy.juxtaposition.coreAdverseLabels,
    adverseMet: anatomy.juxtaposition.adverseMet,
    adverseChecked: anatomy.juxtaposition.adverseChecked,
    totalAnalysisMs: interpretation.timings.totalAnalysisMs,
    modelCalls: interpretation.calls.length,
    promptTokens: interpretation.promptTokens,
    completionTokens: interpretation.completionTokens,
  };
}
