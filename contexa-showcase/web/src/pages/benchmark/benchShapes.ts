import type { BenchmarkReasoning, BenchmarkView, BlindSpot, JudgmentTimingKind } from '../../api/benchmark';

/**
 * The portal's benchmark fields added for the pre-video review (docs/showcase/영상전-검토.md V-01, V-46, V-64), read
 * here so the shared answer types stay as they are; an older portal sends none of them and the views leave them out.
 */

/** A step of an attack run of the kind "other", as the portal scored it (BenchmarkView.JudgmentStep). */
export interface JudgmentStep {
  readonly stepNo: number;
  /** The engine's action; null when the step had no decision of its own. */
  readonly action: string | null;
  /** BEFORE_RESPONSE, NEXT_REQUEST or NONE. */
  readonly applied: string;
  /** Where the answer came from: MODEL, PROPOSAL_CHANGED, FALLBACK, PRIOR_DECISION, STATIC_AUTHORIZATION, NOT_ANALYSED. */
  readonly source: string;
  /** False for a decision from the next request after the last step: it could no longer change the case. */
  readonly applicable: boolean;
}

/** An attack run of the kind "other" (BenchmarkView.JudgmentRun): its case, Contexa's result and every step. */
export interface JudgmentRun {
  readonly runId: string;
  readonly caseKey: string;
  readonly result: string;
  readonly exposedItems: number;
  readonly steps: readonly JudgmentStep[];
}

interface ReviewFields {
  readonly judgmentOthers?: readonly JudgmentRun[];
  readonly riskJudged: {
    readonly runs: number;
    readonly stopped: number;
    readonly kinds?: Readonly<Partial<Record<JudgmentTimingKind, number>>>;
    readonly notStopped?: readonly string[];
  };
}

/** The attack runs of the kind "other", in run order; none from an older portal. */
export function judgmentOthers(view: BenchmarkView): readonly JudgmentRun[] {
  return (view as BenchmarkView & ReviewFields).judgmentOthers ?? [];
}

/** The risky runs by their kind and the cases of those not stopped; null from an older portal. */
export function riskKinds(view: BenchmarkView): {
  readonly kinds: Readonly<Partial<Record<JudgmentTimingKind, number>>>;
  readonly notStopped: readonly string[];
} | null {
  const risk = (view as BenchmarkView & ReviewFields).riskJudged;
  return risk.kinds ? { kinds: risk.kinds, notStopped: risk.notStopped ?? [] } : null;
}

/** The normal cases more than one designed pair names (the totals count each once); none from an older portal. */
export function sharedNormals(proof: BlindSpot): readonly string[] {
  return (proof as BlindSpot & { readonly sharedNormals?: readonly string[] }).sharedNormals ?? [];
}

/** Per run truth and explanation, the decisions by the action each applied; null from an older portal. */
export function mostLikelyActions(
  reasoning: BenchmarkReasoning,
): Readonly<Record<string, Readonly<Record<string, Readonly<Record<string, number>>>>>> | null {
  return (
    (
      reasoning as BenchmarkReasoning & {
        readonly mostLikelyActions?: Readonly<
          Record<string, Readonly<Record<string, Readonly<Record<string, number>>>>>
        >;
      }
    ).mostLikelyActions ?? null
  );
}
