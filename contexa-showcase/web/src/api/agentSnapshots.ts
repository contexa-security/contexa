import { useQueries, useQuery } from '@tanstack/react-query';
import type { AgentCaseView, AgentRunView, BurstSummary } from './agentCase';
import { getJson } from './http';

/**
 * docs/agent Agent중심-화면 AC-5 (D-6): the reference agent runs the portal serves from frozen files
 * (`/api/agent-snapshots`): the case and the run exactly as they were read from a running portal, so a screen shows a
 * stored real run whatever the database holds, and no model is called for it.
 */

export type { BurstSummary };

export interface AgentSnapshotEntry {
  readonly label: string;
  readonly runId: string;
  readonly caseKey: string;
  readonly kind: string;
  readonly why: string;
}

export interface AgentSnapshot extends AgentSnapshotEntry {
  readonly capturedAt: string;
  readonly case: AgentCaseView | null;
  readonly run: AgentRunView;
  readonly summary: BurstSummary;
}

export function useAgentSnapshotIndex() {
  return useQuery({
    queryKey: ['agent-snapshots'],
    queryFn: () => getJson<readonly AgentSnapshotEntry[]>('/api/agent-snapshots'),
    staleTime: Infinity,
    retry: false,
  });
}

/** One frozen run; the label is one of the index's. */
export function useAgentSnapshot(label: string | null) {
  return useQuery({
    queryKey: ['agent-snapshot', label],
    queryFn: () => getJson<AgentSnapshot>(`/api/agent-snapshots/${label}`),
    enabled: label !== null,
    staleTime: Infinity,
    retry: false,
  });
}

/** The frozen run the agent screens show when a visitor has no run of their own and the case has no recording. */
export const REFERENCE_SNAPSHOT = 'T5-confirm-approve';

/**
 * The frozen reference run, read only when the screen has nothing else to show (the visitor sent no run and the case
 * has no recording): then a stored real run stands in, and no model is called for it (AC-5).
 */
export function useReferenceSnapshot(needed: boolean) {
  return useAgentSnapshot(needed ? REFERENCE_SNAPSHOT : null).data ?? null;
}

/** The three bursts the portal measured, each with the flights off (every request analysed) and on. */
export const BURST_CASES = ['M41A', 'M41T', 'M41X'] as const;
export type BurstCase = (typeof BURST_CASES)[number];

export function burstLabel(burst: BurstCase, flights: 'on' | 'off'): string {
  return `${burst}-flights-${flights}`;
}

export interface BurstPair {
  readonly burst: BurstCase;
  readonly off: AgentSnapshot;
  readonly on: AgentSnapshot;
}

/**
 * The three bursts' stored runs, flights off and on: the bursts whose two runs are both read (a missing file leaves its
 * burst out), and whether any is still loading.
 */
export function useBurstSnapshots(): { readonly pending: boolean; readonly bursts: readonly BurstPair[] } {
  const queries = useQueries({
    queries: BURST_CASES.flatMap((burst) =>
      (['off', 'on'] as const).map((flights) => ({
        queryKey: ['agent-snapshot', burstLabel(burst, flights)],
        queryFn: () => getJson<AgentSnapshot>(`/api/agent-snapshots/${burstLabel(burst, flights)}`),
        staleTime: Infinity,
        retry: false,
      })),
    ),
  });
  const bursts: BurstPair[] = [];
  BURST_CASES.forEach((burst, index) => {
    const off = queries[index * 2]?.data;
    const on = queries[index * 2 + 1]?.data;
    if (off && on) {
      bursts.push({ burst, off, on });
    }
  });
  return { pending: queries.some((query) => query.isPending), bursts };
}
