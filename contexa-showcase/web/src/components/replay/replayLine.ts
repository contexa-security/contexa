import type { TFunction } from 'i18next';
import { useLocation } from 'react-router-dom';

/** The measurement's line under a replayed column: how many runs had the same result, or passed after a check. */
export function measuredLine(
  t: TFunction,
  runs: number,
  same: number,
  passedAfterCheck: number,
  normal: boolean,
): string {
  if (normal && passedAfterCheck > 0) {
    return t('hook.measuredAfterCheck', { runs, n: passedAfterCheck });
  }
  return same === runs ? t('hook.measuredSame', { runs }) : t('hook.measuredSome', { runs, same });
}

/**
 * The address of a case's stored real record (D-35) with the way back to the screen the visitor is on; the record
 * page replays the case's recorded or measured run.
 */
export function useRecordPath(caseKey: string): string {
  const location = useLocation();
  return `/replay/${encodeURIComponent(caseKey)}?from=${encodeURIComponent(location.pathname + location.search)}`;
}
