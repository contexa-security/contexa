import { useSearchParams } from 'react-router-dom';
import type {
  BenchmarkRate,
  BenchmarkReasoning,
  BenchmarkView,
  BlindSpot,
  ControlScore,
  JudgmentTimingKind,
} from '../../api/benchmark';
import { formatNumber } from '../format';

/** The five controls in the one order every table of the validation keeps. */
export const CONTROLS = ['A', 'B', 'C1', 'C2', 'D'] as const;
export type ControlKey = (typeof CONTROLS)[number];

const SETTING = /^[0-9a-f]{64}$/;

/** The measurement setting the validation shows (`?setting=`, 64 hex characters), the latest when none is named (ST-56). */
export function useValidationSetting(): string | null {
  const [params] = useSearchParams();
  const asked = params.get('setting');
  return asked && SETTING.test(asked) ? asked : null;
}

/** The case group the controls tab counts (`?suite=`): every case, or a group the server names. */
export function suiteOf(view: BenchmarkView, asked: string | null) {
  const suite = view.suites.find((candidate) => candidate.suite === asked) ?? null;
  return {
    suite,
    controls: suite ? suite.controls : view.controls,
    conclusions: suite ? suite.conclusions : view.conclusions,
  };
}

export function scoreOf(controls: readonly ControlScore[], control: string): ControlScore | null {
  return controls.find((score) => score.control === control) ?? null;
}

/** A share the server worked out, with one decimal (0.8182 → 81.8%). */
export function ratePercent(value: number | null, language: string): string {
  return value === null ? '—' : `${formatNumber(value * 100, language, 1)}%`;
}

/** A rate as "hits / total". */
export function rateCounts(rate: BenchmarkRate, language: string): string {
  return `${formatNumber(rate.hits, language)} / ${formatNumber(rate.total, language)}`;
}

/** A rate's 95% range ("61.5–92.7%"), when the server sent one. */
export function rateRange(rate: BenchmarkRate, language: string): string | null {
  return rate.low === null || rate.high === null
    ? null
    : `${formatNumber(rate.low * 100, language, 1)}–${formatNumber(rate.high * 100, language, 1)}%`;
}

/** The lowest number of attacks an existing control missed: what the summary sets Contexa's misses against. */
export function fewestExistingMisses(controls: readonly ControlScore[]): number | null {
  const misses = controls.filter((score) => score.control !== 'D').map((score) => score.missed);
  return misses.length > 0 ? Math.min(...misses) : null;
}

/**
 * How many times each case was sent, as the server counted the runs (벤치마크 계획 BM-S9: a measurement stopped
 * before its plan sent its cases fewer times than its repeat); an older portal's planned repeat otherwise.
 */
export function sentPerCase(view: BenchmarkView): string {
  const { fewestRunsPerCase: fewest, mostRunsPerCase: most } = view.scope;
  if (fewest !== undefined && most !== undefined && most > 0) {
    return fewest === most ? String(most) : `${fewest}~${most}`;
  }
  return view.scope.protocols.map((protocol) => protocol.repeat).join(', ') || '-';
}

/**
 * The portal's benchmark fields added for the pre-video review (docs/showcase/영상전-검토.md V-01, V-46, V-64), read
 * here so the shared answer types stay as they are; an older portal sends none of them and the views leave them out.
 * Moved with `sentPerCase` from the old benchmark screen (pages/benchmark/benchShapes.ts · benchScope.ts) at I-10
 * (DEC-80).
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
