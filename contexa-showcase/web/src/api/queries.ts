import { skipToken, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import type { RuleCasesView } from '../domain/rules';
import { getJson } from './http';
import type {
  ExecutionSpec,
  ExperienceResult,
  LiveConfig,
  LiveRunView,
  Pair,
  RunScore,
  StatsView,
  VisitorState,
  AnalysisView,
  BaselineCardView,
} from './types';

/** Recorded replays never change once published, so they are cached for the whole visit. */
const STATIC = { staleTime: Infinity, retry: false } as const;

/**
 * The server's score of a run by its one scoring rule (docs/showcase/데모-재설계.md 5.0). The screens show it as is and
 * never judge the answers themselves. `stage` names the point of the run the score is read at (a step finished, a
 * check answered), so each stage reads it once; it is read again each second until the server has stored the
 * `expectedSteps` the screen has already shown.
 */
export function useRunScore(runId: string | null | undefined, stage: string | null, expectedSteps: number) {
  return useQuery({
    queryKey: ['run-score', runId, stage],
    queryFn:
      runId && stage ? () => getJson<RunScore>(`/api/runs/${encodeURIComponent(runId)}/score`) : skipToken,
    staleTime: Infinity,
    retry: 2,
    refetchInterval: (query) => {
      const data = query.state.data;
      return data && data.executedSteps < expectedSteps ? 1000 : false;
    },
  });
}

/** The scores of stored runs that are finished, read once each, in the given order. */
export function useStoredRunScores(runIds: readonly string[]) {
  return useQueries({
    queries: runIds.map((runId) => ({
      queryKey: ['run-score', runId, 'stored'],
      queryFn: () => getJson<RunScore>(`/api/runs/${encodeURIComponent(runId)}/score`),
      ...STATIC,
    })),
  });
}

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

/** The cases of the rule-limits scene: the latest real run of every scenario with a ground truth. */
export function useRuleCases() {
  return useQuery({
    queryKey: ['rule-cases'],
    queryFn: () => getJson<RuleCasesView>('/api/rules/cases'),
    staleTime: 60_000,
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

const LIVE_ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED']);
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
        // The visitor's list of runs (the journey) now holds this run; screens that read it see it at once.
        void queryClient.invalidateQueries({ queryKey: ['journey'] });
        void queryClient.invalidateQueries({ queryKey: ['act-end'] });
        // Records a screen asked for before the run's end (its anatomies are built at the end) are read again.
        if (run.runId) {
          void queryClient.invalidateQueries({ queryKey: ['anatomy', run.runId] });
          void queryClient.invalidateQueries({ queryKey: ['step-result', run.runId] });
        }
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

/** What Contexa knows about an employee before the visitor acts as them; it changes only with a new template. */
/** An employee's usual-behaviour card; nothing is asked before the employee is known. */
export function useBaseline(employee: string | null) {
  return useQuery({
    queryKey: ['baseline', employee],
    queryFn: employee
      ? () => getJson<BaselineCardView>(`/api/live/baseline/${encodeURIComponent(employee)}`)
      : skipToken,
    staleTime: 5 * 60_000,
    retry: false,
  });
}

/**
 * The engine's analysis of a step of the visitor's current run, read often while it goes; 404 before control D's
 * request of the step was sent.
 */
export function useLiveAnalysis(liveRunId: string | null, step: number, active: boolean) {
  return useQuery({
    queryKey: ['live-analysis', liveRunId, step],
    queryFn: () => getJson<AnalysisView>(`/api/live/runs/current/analysis?step=${step}`),
    enabled: active && liveRunId !== null,
    retry: false,
    // Read until the engine applied its decision and the decision block came with it, or it reported an error; the
    // stages and the decision after that do not change.
    refetchInterval: (query) => (analysisSettled(query.state.data) ? false : 300),
  });
}

export function analysisSettled(view: AnalysisView | undefined): boolean {
  return (
    view?.stages.some(
      (stage) =>
        (stage.type === 'DECISION_APPLIED' && stage.action !== null && view.decision !== null) ||
        stage.type === 'ANALYSIS_ERROR',
    ) ?? false
  );
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
