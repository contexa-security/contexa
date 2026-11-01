import type { RecapLine } from '../../api/journey';

/**
 * The visitor's latest finished run of a case on the main flow (lab runs are the lab's). `key` may name several cases
 * (the agent's track opens more than one); `classification` keeps only the runs of cases of that kind. Moved from the
 * old screens' pages/main/latestRun.ts at I-10 (DEC-80).
 */
export function latestOwnRun(
  runs: readonly RecapLine[] | undefined,
  key: string | readonly string[],
  classification?: string,
): RecapLine | null {
  const keys = typeof key === 'string' ? [key] : key;
  const own = (runs ?? []).filter(
    (run) =>
      keys.includes(run.scenarioKey) &&
      !run.lab &&
      run.status === 'COMPLETED' &&
      (classification === undefined || run.classification === classification),
  );
  return own.length > 0 ? (own[own.length - 1] ?? null) : null;
}
