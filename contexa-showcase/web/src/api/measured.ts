import { skipToken, useQuery } from '@tanstack/react-query';
import { getJson } from './http';

/** One run of a case in the current measurement, as the portal scored it (MeasuredCases). */
export interface MeasuredRun {
  readonly runId: string;
  readonly startedAt: string | null;
  /** Contexa's business result over the run. */
  readonly result: string;
  readonly engineAction: string | null;
  /** The engine's analysis time of the first request. */
  readonly analysisMs: number | null;
  readonly exposedItems: number;
  readonly reissueOutcome: string | null;
  /** From the additional check to the re-issued request. */
  readonly releaseMillis: number | null;
  /** How long Contexa's application took to answer the first request (what a synchronous decision holds). */
  readonly responseMs: number | null;
}

export interface MeasuredRange {
  readonly min: number;
  readonly max: number;
}

/**
 * A case's runs in the latest measurement of the current setting with the counts and ranges the "measured N times"
 * lines need, all counted by the portal.
 */
export interface MeasuredCase {
  readonly caseKey: string;
  readonly settingHash: string;
  readonly protocolId: string;
  readonly runs: number;
  readonly results: Readonly<Record<string, number>>;
  readonly allSame: boolean;
  readonly analysisMs: MeasuredRange | null;
  readonly exposedItems: MeasuredRange | null;
  readonly list: readonly MeasuredRun[];
  /**
   * The latest measured run of the case whose additional check was answered and whose request went out again, from any
   * setting; `current` says whether it is the current setting's. Null when no such run exists.
   */
  readonly resumed: {
    readonly runId: string;
    readonly startedAt: string;
    readonly settingHash: string;
    readonly current: boolean;
  } | null;
  /** The shortest and longest time Contexa's application took to answer the first request. */
  readonly responseMs: MeasuredRange | null;
  /** The run whose analysis time is in the middle: the example a screen shows of the measurement. */
  readonly middleRun: string | null;
}

/** 404 when the case has no run in the current measurement; the line is then left out. */
export function useMeasuredCase(caseKey: string | null) {
  return useQuery({
    queryKey: ['measured', caseKey],
    queryFn: caseKey
      ? () => getJson<MeasuredCase>(`/api/cases/${encodeURIComponent(caseKey)}/measured`)
      : skipToken,
    staleTime: 60_000,
    retry: false,
  });
}
