import type { RecapLine } from '../../api/journey';

/** The visitor's latest finished run of a case on the main flow (lab runs are the lab's). */
export function latestOwnRun(runs: readonly RecapLine[] | undefined, key: string): RecapLine | null {
  const own = (runs ?? []).filter((run) => run.scenarioKey === key && !run.lab && run.status === 'COMPLETED');
  return own.length > 0 ? (own[own.length - 1] ?? null) : null;
}
