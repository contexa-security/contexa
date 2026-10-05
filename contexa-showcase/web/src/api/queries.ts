import { useMutation, useQuery } from '@tanstack/react-query';
import { getJson, HttpError, postJson } from './http';
import type {
  Choice,
  CombinationGrid,
  CombinationView,
  ExecutionSpec,
  LiveConfig,
  LiveRunView,
  Pair,
  PairSummary,
  PredictionResult,
  VisitorState,
} from './types';

/** Recorded replays never change once published, so they are cached for the whole visit. */
const STATIC = { staleTime: Infinity, retry: false } as const;

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
  return useQuery({ queryKey: ['visitor'], queryFn: () => getJson<VisitorState>('/api/visitor'), retry: false });
}

export function usePrediction() {
  return useMutation({
    mutationFn: async ({ scene, choice }: { scene: string; choice: Choice }) => {
      const result = await postJson<PredictionResult>('/api/predictions', { scene, choice });
      // 409: this scene was already predicted; the stored first vote is returned and counts.
      if (result.status !== 201 && result.status !== 409) {
        throw new HttpError(result.status, `prediction refused with ${result.status}`);
      }
      return result.body;
    },
  });
}

/** The development single space (P3); a 404 means it is not open on this portal. */
export function useLiveConfig() {
  return useQuery({ queryKey: ['live-config'], queryFn: () => getJson<LiveConfig>('/api/live/config'), ...STATIC });
}

const LIVE_ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE']);

/** The visitor's live run, polled every second while it is still going. */
export function useLiveRun(enabled: boolean) {
  return useQuery({
    queryKey: ['live-run'],
    queryFn: () => getJson<LiveRunView>('/api/live/runs/current'),
    enabled,
    retry: false,
    refetchInterval: (query) => (query.state.data && LIVE_ACTIVE.has(query.state.data.status) ? 1000 : false),
  });
}

/** The boundary map of one employee, ticket and device: stored real runs only. */
export function useCombinationGrid(employee: string, ticket: string, device: string) {
  return useQuery({
    queryKey: ['grid', employee, ticket, device],
    queryFn: () =>
      getJson<CombinationGrid>(
        `/api/combinations?employee=${encodeURIComponent(employee)}&ticket=${ticket}&device=${device}`,
      ),
    retry: false,
  });
}

export function useCombination(key: string) {
  return useQuery({
    queryKey: ['combination', key],
    queryFn: () => getJson<CombinationView>(`/api/combinations/${encodeURIComponent(key)}`),
    retry: false,
  });
}
