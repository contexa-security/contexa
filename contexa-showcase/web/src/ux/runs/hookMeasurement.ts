import { useBenchmark, type BenchmarkView } from '../../api/benchmark';
import type { HookColumn } from '../../api/hook';

export interface HookRepeats {
  /** The case's runs in the measurement. */
  readonly runs: number;
  /** Runs whose Contexa result is the published run's own. */
  readonly same: number;
}

/**
 * How often the published recorded run's result came back (DEC-83): over every run of the case in the measurement the
 * scenario validation counts (one setting, all its protocols), when the published run is one of them; otherwise the
 * portal's own count, which covers the run's protocol only. The measurement of 2026-11-01 ran five protocols of one
 * repeat each (DEC-74), so the portal alone would say "1 of 1" and leave the other runs out.
 */
export function hookRepeats(column: HookColumn, benchmark: BenchmarkView | null | undefined): HookRepeats {
  const kase = benchmark?.cases.find((candidate) => candidate.key === column.caseKey) ?? null;
  const results = kase?.runResults ?? null;
  const own = results?.[column.runId]?.D ?? null;
  if (!kase || !results || own === null || !kase.runIds.includes(column.runId)) {
    return { runs: column.measurement.runs, same: column.measurement.sameResult };
  }
  return { runs: kase.runs, same: kase.runIds.filter((runId) => results[runId]?.D === own).length };
}

export function useHookRepeats(column: HookColumn | null): HookRepeats | null {
  const benchmark = useBenchmark(null);
  return column ? hookRepeats(column, benchmark.data) : null;
}
