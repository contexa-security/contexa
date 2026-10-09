import { useQuery } from '@tanstack/react-query';
import { getJson } from './http';
import type { ControlId } from '../domain/verdict';

/**
 * The benchmark of one measurement setting (docs/showcase/데모-재설계.md 5A.2), as the portal counts it
 * (BenchmarkService): every number comes from the stored protocol runs by the one scoring rule; nothing is computed
 * here.
 */
export interface BenchmarkRate {
  readonly hits: number;
  readonly total: number;
  readonly rate: number | null;
  readonly low: number | null;
  readonly high: number | null;
  /** Counted over fewer than ten runs: shown as preliminary. */
  readonly preliminary: boolean;
}

export interface BenchmarkSpec {
  readonly settingHash: string;
  readonly chatModel: string;
  readonly modelSettings: Readonly<Record<string, unknown>> | null;
  readonly codeCommit: string;
  readonly engineVersion: string;
  readonly ruleVersion: string;
  readonly contractVersion: string;
  readonly templates: readonly string[];
  readonly templateVersions: readonly string[];
  readonly promptHashes: readonly string[];
  readonly protocolRuns: number;
  readonly firstRunAt: string;
  readonly lastRunAt: string;
}

export interface BenchmarkProtocol {
  readonly protocolId: string;
  readonly repeat: number;
  readonly cases: number;
  readonly plannedRuns: number;
  readonly startedAt: string;
  readonly finishedAt: string | null;
  readonly completedRuns: number;
  readonly failedRuns: number;
  readonly forcedRuns: number;
}

export interface BenchmarkScope {
  readonly runs: number;
  readonly attackRuns: number;
  readonly normalRuns: number;
  readonly otherRuns: number;
  readonly cases: number;
  readonly protocols: readonly BenchmarkProtocol[];
}

export interface ControlScore {
  readonly control: ControlId;
  readonly stopped: BenchmarkRate;
  readonly stoppedAny: BenchmarkRate;
  readonly stoppedMacro: number | null;
  /** The mean of the per-case detection rates (stopped at some step), the detection bar's rule. */
  readonly stoppedAnyMacro: number | null;
  readonly falseBlock: BenchmarkRate;
  readonly friction: BenchmarkRate;
  readonly falseBlockMacro: number | null;
  readonly attackUnresolved: number;
  readonly normalUnresolved: number;
  readonly exposedItems: number;
  /** Attack runs stopped only after some items left, counted by the server. */
  readonly partlyStopped: number;
  /** Attack runs that nothing stopped, counted by the server. */
  readonly missed: number;
  /** Normal runs that went through without an additional check, counted by the server. */
  readonly normalPassed: number;
  /** Normal runs not halted (passed with or without a check), with the interval: the summary's third column. */
  readonly notBlocked: BenchmarkRate;
}

/** The approaches with the highest count and that count; no approach when the highest count is zero. */
export interface BenchmarkPick {
  readonly controls: readonly ControlId[];
  readonly hits: number;
  readonly total: number;
}

/** The summary's three questions answered from the scores (bench-1); a tie names every tied approach. */
export interface BenchmarkConclusions {
  readonly mostStopped: BenchmarkPick;
  readonly mostFalseBlock: BenchmarkPick;
  readonly cleanMostStopped: BenchmarkPick;
}

export interface BenchmarkCase {
  readonly key: string;
  readonly classification: string;
  readonly title: Readonly<Record<string, string>>;
  readonly runs: number;
  readonly definitionSha256: readonly string[];
  readonly results: Readonly<Record<string, Readonly<Record<string, number>>>>;
  readonly engineActions: Readonly<Record<string, number>>;
  readonly engineVerdicts: Readonly<Record<string, number>>;
  readonly decisionSources: Readonly<Record<string, number>>;
  readonly runIds: readonly string[];
  readonly risk: {
    readonly min: number | null;
    readonly max: number | null;
    readonly scored: number;
    readonly decisions: number;
  };
  /** Per control: runs handled as the ground truth says over scored runs; empty without a ground truth. */
  readonly cells: Readonly<
    Partial<
      Record<
        ControlId,
        {
          readonly right: number;
          readonly counted: number;
          /** The server's reading of the two counts. */
          readonly state: 'NONE' | 'RIGHT' | 'WRONG' | 'MIXED';
        }
      >
    >
  >;
  /** Contexa got at least one scored run of the case wrong (the case list's filter). */
  readonly contexaWrong: boolean;
  /** An attack case Contexa let through in every run (the limits screen). */
  readonly missedEveryRun: boolean;
}

/**
 * How Contexa's answer to an attack run came about: refused by the static authorization, decided before the response,
 * stopped from the next request after some items left, let through because every decision was to allow, or other.
 */
export type JudgmentTimingKind =
  'STATIC_REFUSAL' | 'BEFORE_RESPONSE' | 'NEXT_REQUEST' | 'JUDGED_ALLOW' | 'OTHER';

/** A named group of cases scored apart (portal BenchmarkView.Suite). */
export interface BenchmarkSuite {
  readonly suite: string;
  readonly cases: readonly string[];
  readonly runs: number;
  readonly controls: readonly ControlScore[];
  readonly conclusions: BenchmarkConclusions;
}

export interface WrongRun {
  readonly runId: string;
  readonly caseKey: string;
  readonly classification: string;
  readonly result: string;
  readonly exposedItems: number;
  readonly stepNo: number | null;
  readonly finalAction: string | null;
  readonly riskScore: number | null;
  readonly reasoning: string | null;
  readonly coreAdverseMet: number | null;
  readonly startedAt: string;
}

export interface BenchmarkEngine {
  readonly decisions: number;
  readonly actions: Readonly<Record<string, number>>;
  readonly unresolved: number;
  readonly analysisP50Ms: number | null;
  readonly analysisP95Ms: number | null;
  readonly analysisMeasured: number;
  readonly costPerDecisionUsd: number | null;
  readonly priceSource: string | null;
  readonly promptTokens: number;
  readonly cachedTokens: number;
  readonly completionTokens: number;
  readonly tokensPerDecision: number | null;
  readonly tokensMeasured: number;
  readonly modelCallsPerDecision: number | null;
  readonly modelCalls: number;
}

export interface BenchmarkObservations {
  readonly liveRuns: number;
  readonly labRuns: number;
  readonly composedRuns: number;
  readonly predictionsAll: number;
  readonly predictions: BenchmarkRate;
  readonly unsurePredictions: number;
  /** Calls on designed cases: the scored ones and the "unsure" ones, counted by the server. */
  readonly designedPredictions: number;
  readonly assessments: number;
  readonly assessors: number;
  readonly soundShareWeighted: number | null;
  readonly verdicts: Readonly<Record<string, number>>;
  readonly reasons: Readonly<Record<string, number>>;
  readonly delayHours: number;
}

export interface BenchmarkView {
  readonly computedAt: string;
  readonly notices: readonly string[];
  readonly specs: readonly BenchmarkSpec[];
  readonly spec: BenchmarkSpec | null;
  readonly scope: BenchmarkScope;
  readonly controls: readonly ControlScore[];
  readonly cases: readonly BenchmarkCase[];
  /** Every run Contexa got wrong (an attack let through, a normal task stopped), newest first and not cut. */
  readonly wrongRuns: readonly WrongRun[];
  /** The number of wrong runs, as the server counted them. */
  readonly wrongRunCount: number;
  /** Runs with a ground truth where the engine made no real decision, counted apart from the wrong runs. */
  readonly unresolvedRuns: number;
  /** Each named case group scored apart, such as the cases the rule controls were not written for. */
  readonly suites: readonly BenchmarkSuite[];
  /** Contexa's attack runs the model judged risky (a decision not to allow), and how many of them were stopped. */
  readonly riskJudged: { readonly runs: number; readonly stopped: number };
  /** Contexa's attack runs by how its answer came about; every kind is present, in this order. */
  readonly judgmentTiming: Readonly<Record<JudgmentTimingKind, number>>;
  readonly engine: BenchmarkEngine | null;
  readonly observations: BenchmarkObservations;
  readonly protocolRunsWithoutSetting: number;
  /** How many measured cases each classification has, and how many of them Contexa got wrong, counted by the server. */
  readonly caseCounts: Readonly<Record<'THREAT' | 'NORMAL' | 'UNCERTAIN', number>>;
  readonly contexaWrongCases: Readonly<Record<'THREAT' | 'NORMAL' | 'UNCERTAIN', number>>;
  readonly conclusions: BenchmarkConclusions;
  /** The attack cases Contexa let through in every run, in case order. */
  readonly missedEveryRunCases: readonly string[];
}

/** The address of a setting's raw records (every counted protocol run with its score), to download. */
export function benchmarkRunsHref(setting: string | null): string {
  return `/api/benchmark/runs${setting ? `?setting=${encodeURIComponent(setting)}` : ''}`;
}

/** The benchmark of a measurement setting; the latest one when none is named (R-13). */
export function useBenchmark(setting: string | null) {
  return useQuery({
    queryKey: ['benchmark', setting],
    queryFn: () =>
      getJson<BenchmarkView>(`/api/benchmark${setting ? `?setting=${encodeURIComponent(setting)}` : ''}`),
    staleTime: 60_000,
    retry: false,
  });
}
