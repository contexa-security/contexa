import { useQueries, useQuery } from '@tanstack/react-query';
import { useHook } from '../../api/hook';
import { getJson } from '../../api/http';
import { useJourney } from '../../api/journey';
import { useLiveConfig, useStoredRunScores, useVisitor } from '../../api/queries';
import type { Localized, Pair, PairSummary, RunScore } from '../../api/types';
import { decidingStep } from '../simulate/person';

/** Where a row of the decision log comes from (DEC-40): the visitor's own run, a public recorded run, a measured run. */
export type RunSource = 'own' | 'public' | 'measured';

export interface LogRow {
  readonly runId: string;
  readonly source: RunSource;
  readonly scenarioKey: string;
  /** A run of a composed condition (the policy simulator's composition). */
  readonly lab: boolean;
  /** When the run was recorded: its start (own, public) or its end (measured); null when unknown. */
  readonly at: string | null;
  /** A recorded replay scene's situation sentence (공개 녹화 실행); null for any other run. */
  readonly sentence: Localized | null;
  /** The server's score of the run; null while it is read or when it could not be read. */
  readonly score: RunScore | null;
}

const LONG = { staleTime: 300_000, retry: false } as const;

/**
 * The decision log's rows (DEC-40, DEC-41): the visitor's own runs, the public recorded runs (the published pair of the
 * start of the demo and the recorded replays) and the measured runs of the latest setting, each run once, newest first.
 * A source that cannot be read is named in `failed`; the others still fill the log (ST-40).
 */
export function useRunLog() {
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const hook = useHook();
  const measured = useQuery({
    queryKey: ['benchmark-runs'],
    queryFn: () => getJson<{ readonly settingHash: string | null; readonly runs: readonly RunScore[] }>('/api/benchmark/runs'),
    ...LONG,
  });
  const pairs = useQuery({ queryKey: ['pairs'], queryFn: () => getJson<PairSummary[]>('/api/pairs'), ...LONG });
  const recorded = (pairs.data ?? []).filter((pair) => pair.recorded).map((pair) => pair.key);
  const replays = useQueries({
    queries: recorded.map((key) => ({
      queryKey: ['replay', key],
      queryFn: () => getJson<Pair>(`/api/replays/${encodeURIComponent(key)}`),
      ...LONG,
    })),
  });

  const own: Omit<LogRow, 'score'>[] = (journey.data?.runs ?? [])
    .filter((run) => run.status === 'COMPLETED')
    .map((run) => ({
      runId: run.runId,
      source: 'own',
      scenarioKey: run.scenarioKey,
      lab: run.lab,
      at: run.startedAt ?? null,
      sentence: null,
    }));
  const published: Omit<LogRow, 'score'>[] = [
    ...(hook.data
      ? [hook.data.attacker, hook.data.owner].map((column) => ({
          runId: column.runId,
          source: 'public' as const,
          scenarioKey: column.caseKey,
          lab: false,
          at: column.startedAt,
          sentence: null,
        }))
      : []),
    ...replays.flatMap((replay) =>
      (replay.data?.scenes ?? []).map((scene) => ({
        runId: scene.runId,
        source: 'public' as const,
        scenarioKey: replay.data?.key ?? '',
        lab: false,
        at: scene.recordedAt,
        sentence: scene.sentence ?? null,
      })),
    ),
  ];
  const seen = new Set<string>();
  const unique = (rows: readonly Omit<LogRow, 'score'>[]) =>
    rows.filter((row) => {
      if (!row.runId || seen.has(row.runId)) {
        return false;
      }
      seen.add(row.runId);
      return true;
    });
  const ownRows = unique(own);
  const publicRows = unique(published);
  const measuredRows = (measured.data?.runs ?? []).filter((run) => !seen.has(run.runId));
  const scores = useStoredRunScores([...ownRows, ...publicRows].map((row) => row.runId));
  const scoreOf = new Map(
    [...ownRows, ...publicRows].map((row, index) => [row.runId, scores[index]?.data ?? null] as const),
  );
  const rows: LogRow[] = [
    ...[...ownRows, ...publicRows].map((row) => ({ ...row, score: scoreOf.get(row.runId) ?? null })),
    ...measuredRows.map((run) => ({
      runId: run.runId,
      source: 'measured' as const,
      scenarioKey: run.scenarioKey,
      lab: false,
      at: run.finishedAt ?? null,
      sentence: null,
      score: run,
    })),
  ].sort((a, b) => (b.at ?? '').localeCompare(a.at ?? ''));
  const failed: RunSource[] = [
    ...(journey.isError ? (['own'] as const) : []),
    ...(hook.isError || pairs.isError || replays.some((replay) => replay.isError) ? (['public'] as const) : []),
    ...(measured.isError ? (['measured'] as const) : []),
  ];
  return {
    pending: measured.isPending && hook.isPending,
    rows,
    failed,
  };
}

/** The scenario's name: the one stored with the run, else the live catalogue's, else its key. */
export function useScenarioTitle() {
  const config = useLiveConfig();
  return (key: string, stored: Localized | null | undefined, language: string): string => {
    const lang = language === 'ko' ? 'ko' : 'en';
    const named = stored ?? [...(config.data?.scenarios ?? []), ...(config.data?.agentCases ?? [])].find(
      (scenario) => scenario.key === key,
    )?.title;
    return named?.[lang] ?? named?.en ?? key;
  };
}

/** The decision the log shows for a run: the request it was decided at (the first restriction, else the last). */
export function decisionOf(score: RunScore | null): { readonly step: number; readonly action: string | null } {
  if (!score) {
    return { step: 1, action: null };
  }
  const step = decidingStep(score);
  return { step, action: score.verdicts.find((verdict) => verdict.score.stepNo === step)?.score.finalAction ?? null };
}

const STOPPING = new Set(['STOPPED', 'HALTED', 'PARTLY_STOPPED']);

/** How many of the four existing controls stopped the run (fully or in part). */
export function existingStops(score: RunScore | null): number | null {
  if (!score) {
    return null;
  }
  return (['A', 'B', 'C1', 'C2'] as const).filter((control) => STOPPING.has(score.business[control]?.result ?? '')).length;
}
