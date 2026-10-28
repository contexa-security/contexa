import type { useTranslation } from 'react-i18next';
import type { BurstSummary } from '../../api/agentCase';

type T = ReturnType<typeof useTranslation>['t'];

/** The rows of a burst's counts, each a number the portal made from the run's steps. */
export const BURST_ROWS = [
  'requests',
  'delivered',
  'refused',
  'busy',
  'withVerdict',
  'modelCalls',
  'deliveredAfterFirstStop',
] as const;

/** The request control D first stopped the work at, or the words for a burst it never stopped. */
export function firstStop(t: T, summary: BurstSummary): string {
  return summary.firstStopStep === null ? t('main.6-7.neverStopped') : String(summary.firstStopStep);
}
