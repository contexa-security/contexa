import type { TFunction } from 'i18next';
import type { ReactNode } from 'react';
import type { AdverseLabel } from '../../api/anatomy';
import type { LiveDecision } from '../../api/types';

/**
 * The decision cell's contents from control D's decision block (panel slide, decision 7): a contract sentence in its
 * fixed Korean with the note that the rules set it, otherwise the note that the engine wrote it itself and the original
 * behind the "original" tag. Counts are the portal's.
 */
/**
 * The approval the engine read, in the visitor's words: the requirement and whether an approval is
 * missing, as the core's inspector read their labels; of a v20 decision whether PolicySatisfied states
 * the policy it states as met (N-DEP-2). Null when the engine read no requirement.
 */
export function approvalFact(t: TFunction, labels: readonly AdverseLabel[]): string | null {
  const met = (name: string) => labels.some((label) => label.label === name && label.met);
  if (met('approvalrequired')) {
    return t(met('approvalmissing') ? 'e1.reason.noApproval' : 'e1.reason.approval');
  }
  const policy = labels.find((label) => label.label === 'policysatisfied' && label.values.length > 0);
  return policy ? t(policy.met ? 'e1.reason.policyNotMet' : 'e1.reason.policyMet') : null;
}

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
