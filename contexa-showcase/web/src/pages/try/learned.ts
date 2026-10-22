import type { TFunction } from 'i18next';
import type { DecisionAnatomyView } from '../../api/anatomy';
import type { RecapLine } from '../../api/journey';
import { count } from '../../journey/format';

/**
 * The learned-requests line of screens 3-3 and 3-4 (화면재편-기획안 11.3, "learned requests n"): the engine's learned
 * count when the run started and when it ended, as the run's record holds them; nothing is worked out on the screen.
 */
export function learnedText(
  t: TFunction,
  language: string,
  figures: DecisionAnatomyView['figures'] | null | undefined,
): string {
  const from = figures?.baselineBefore ?? null;
  const to = figures?.baselineAfter ?? null;
  if (from === null || to === null) {
    return t('p3.stack.learned.none');
  }
  return t(from === to ? 'p3.stack.learned.same' : 'p3.stack.learned.changed', {
    from: count(from, language),
    to: count(to, language),
  });
}

/** The visitor's latest completed run of a case in the experience (lab runs left out, as the part's wrap-up does). */
export function latestRun(runs: readonly RecapLine[] | undefined, caseKey: string): string | null {
  return (
    [...(runs ?? [])]
      .reverse()
      .find((line) => line.scenarioKey === caseKey && line.status === 'COMPLETED' && !line.lab)?.runId ?? null
  );
}
