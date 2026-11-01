import type { DecisionAnatomyView } from '../../../api/anatomy';

/** Why a request has no decision of its own (ST-44): an earlier decision, the sign-in check, or a technical failure. */
export function noDecisionKey(anatomy: DecisionAnatomyView): string | null {
  const recorded = anatomy.interpretation.recorded;
  if (recorded.unresolved || recorded.failureType) {
    return 'ux.detail.none.failed';
  }
  if (recorded.finalAction !== null) {
    return null;
  }
  const source = anatomy.truth.verdict?.source ?? null;
  return source === 'PRIOR_DECISION'
    ? 'ux.detail.none.prior'
    : source === 'STATIC_AUTHORIZATION'
      ? 'ux.detail.none.signIn'
      : 'ux.detail.none.other';
}
