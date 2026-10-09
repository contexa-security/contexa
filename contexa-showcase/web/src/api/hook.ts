import { useQuery } from '@tanstack/react-query';
import { getJson } from './http';
import type { StepResult } from './types';

/**
 * The first screen's replay (portal HookViews): the operator-designated measured run of each case with every
 * approach's recorded result, and the same measurement's runs of the case as the server counted them.
 */
export interface HookMeasurement {
  readonly protocolId: string;
  readonly runs: number;
  /** Runs whose Contexa result is the representative run's. */
  readonly sameResult: number;
  /** Runs whose work went on after the additional check was answered. */
  readonly passedAfterCheck: number;
  /** Contexa's business result over the measurement's runs of the case, by result name. */
  readonly results: Readonly<Record<string, number>>;
}

export interface HookColumn {
  readonly caseKey: string;
  readonly runId: string;
  readonly startedAt: string;
  readonly result: StepResult;
  /** Contexa's business result of the representative run. */
  readonly business: string | null;
  /** Whether each approach answered the case right by the one scoring rule; an approach left out is neither. */
  readonly correct?: Readonly<Partial<Record<string, boolean>>>;
  /** The additional check at the replayed request; null without one. */
  readonly check: {
    readonly stepNo: number;
    readonly answered: boolean;
    readonly reissueOutcome: string | null;
    readonly releaseMillis: number | null;
  } | null;
  readonly measurement: HookMeasurement;
}

export interface HookView {
  readonly attacker: HookColumn;
  readonly owner: HookColumn;
  /** Every measured attacker run was stopped and every measured real-employee run went through. */
  readonly distinguished: boolean;
  /** When the first of the two runs' model call texts reaches the retention period. */
  readonly textsKeptUntil: string | null;
}

/** 404 until the operator designated the two runs; the screen then shows its unavailable state. */
export function useHook() {
  return useQuery({
    queryKey: ['hook'],
    queryFn: () => getJson<HookView>('/api/hook'),
    staleTime: 60_000,
    retry: false,
  });
}
