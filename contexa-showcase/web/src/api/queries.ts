import { skipToken, useQuery, useQueryClient } from '@tanstack/react-query';
import { getJson } from './http';
import type {
  ExecutionSpec,
  ExperienceResult,
  LiveConfig,
  LiveRunView,
  Pair,
  PairSummary,
  StatsView,
  StepResult,
  VisitorState,
} from './types';

/** Recorded replays never change once published, so they are cached for the whole visit. */
const STATIC = { staleTime: Infinity, retry: false } as const;

/** The visitor's result of a pair; it depends on the visitor's votes, so it is read fresh. */
export function useExperienceResult(pairKey: string | undefined) {
  return useQuery({
    queryKey: ['result', pairKey],
    queryFn: () => getJson<ExperienceResult>(`/api/results/${encodeURIComponent(pairKey ?? '')}`),
    enabled: Boolean(pairKey),
    retry: false,
  });
}

/** The statistics are counted on the server and cached there for a minute. */
export function useStats() {
  return useQuery({
    queryKey: ['stats'],
    queryFn: () => getJson<StatsView>('/api/stats'),
    staleTime: 60_000,
    retry: false,
  });
}

export function usePairs() {
  return useQuery({ queryKey: ['pairs'], queryFn: () => getJson<PairSummary[]>('/api/pairs'), ...STATIC });
}

export function useReplay(pairKey: string | undefined) {
  return useQuery({
    queryKey: ['replay', pairKey],
    queryFn: () => getJson<Pair>(`/api/replays/${encodeURIComponent(pairKey ?? '')}`),
    enabled: Boolean(pairKey),
    ...STATIC,
  });
}

export function useSpec(specHash: string | undefined) {
  return useQuery({
    queryKey: ['spec', specHash],
    queryFn: () => getJson<ExecutionSpec>(`/api/specs/${specHash ?? ''}`),
    enabled: Boolean(specHash),
    ...STATIC,
  });
}

/** Reading the visitor state issues the visitor cookie and the CSRF cookie before the first vote. */
export function useVisitor() {
  return useQuery({
    queryKey: ['visitor'],
    queryFn: () => getJson<VisitorState>('/api/visitor'),
    retry: false,
  });
}

/** The development single space (P3); a 404 means it is not open on this portal. */
export function useLiveConfig() {
  return useQuery({
    queryKey: ['live-config'],
    queryFn: () => getJson<LiveConfig>('/api/live/config'),
    ...STATIC,
  });
}

const LIVE_ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE']);
const LIVE_ENDED = new Set(['COMPLETED', 'FAILED', 'EXPIRED']);

/** While answers arrive they are read often enough to appear one by one; waits are read once a second. */
const LIVE_ARRIVING = new Set(['STARTING', 'RUNNING']);

/** The visitor's live run, polled while it is still going. */
export function useLiveRun(enabled: boolean) {
  const queryClient = useQueryClient();
  return useQuery({
    queryKey: ['live-run'],
    queryFn: async () => {
      const run = await getJson<LiveRunView>('/api/live/runs/current');
      if (LIVE_ENDED.has(run.status)) {
        // An ended run is kept by its ID, so a screen still shows it after the visitor's next run starts.
        queryClient.setQueryData(['live-ended', run.liveRunId], run);
        void queryClient.invalidateQueries({ queryKey: ['live-config'] });
      }
      return run;
    },
    enabled,
    retry: false,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (!status || !LIVE_ACTIVE.has(status)) {
        return false;
      }
      return LIVE_ARRIVING.has(status) ? 250 : 1000;
    },
  });
}

/** A live run as it ended, kept by {@link useLiveRun}; it never changes. */
export function useEndedRun(liveRunId: string | null) {
  return useQuery<LiveRunView>({
    queryKey: ['live-ended', liveRunId],
    queryFn: skipToken,
    staleTime: Infinity,
    gcTime: Infinity,
  });
}

/**
 * The full result of the visitor's completed live run, with each control's evidence. The server answers for the current
 * run only, so it is read while that run is current and kept once read: it never changes.
 */
export function useLiveResult(liveRunId: string | null, current: boolean) {
  return useQuery({
    queryKey: ['live-result', liveRunId],
    queryFn: () => getJson<StepResult>('/api/live/runs/current/result'),
    enabled: liveRunId !== null && current,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: 2,
  });
}

