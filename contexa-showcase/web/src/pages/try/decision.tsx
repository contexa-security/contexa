import type { TFunction } from 'i18next';
import type { ReactNode } from 'react';
import type { LiveDecision } from '../../api/types';

/**
 * The decision cell's contents from control D's decision block (panel slide, decision 7): a contract sentence in its
 * fixed Korean with the note that the rules set it, otherwise the note that the engine wrote it itself and the original
 * behind the "original" tag. Counts are the portal's.
 */
export function decisionDetail(t: TFunction, decision: LiveDecision) {
  const canonical = decision.reason?.canonical ?? null;
  const plain: ReactNode = canonical ? (
    <>
      {t(`reason.canonical.${canonical}`, { defaultValue: decision.reason?.reasoning ?? '' })}{' '}
      <span>({t('e1.reason.canonical')})</span>
    </>
  ) : (
    t('e1.reason.free')
  );
  return {
    plain,
    original: decision.reason?.reasoning ?? null,
    cited: decision.reason?.evidenceRefs ?? [],
    riskScore: decision.riskScore,
    confidence: decision.confidence,
    inspector: {
      met: decision.adverseMet,
      total: decision.adverseChecked,
      names: decision.adverseLabels
        .filter((label) => label.met)
        .map((label) => t(`adverse.${label.label}`, { defaultValue: label.label })),
    },
  };
}
