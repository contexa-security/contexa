import type { AgentRunView } from '../../../api/agentCase';
import type { DecisionAnatomyView, StoredCheck } from '../../../api/anatomy';
import type { TeasersView } from '../../../api/teasers';

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

/**
 * When the decision applied: while the response was sent when the stored step result says a streamed response was cut
 * (판정층 8절 9), else the decision record's own timing.
 */
export function appliedKey(timing: string | null | undefined, applied: string | null): string | null {
  if (timing === 'MID_RESPONSE') {
    return 'ux.detail.applied.MID_RESPONSE';
  }
  if (!applied) {
    return null;
  }
  return `ux.live.applied.${applied === 'NEXT_REQUEST' ? 'NEXT_REQUEST' : 'BEFORE_RESPONSE'}`;
}

/** A stored step-up's result as recorded: its reason, else passed when answered, else still going. */
export function checkResult(check: StoredCheck): string {
  return check.reason ?? (check.answered ? 'DONE' : 'other');
}

/** The step-up outcomes in the order the old details listed them; an outcome the portal adds later comes last. */
const OUTCOME_ORDER = ['ANSWERED', 'NO_MAILBOX', 'ABANDONED', 'EXPIRED', 'WRONG_CODE_LIMIT', 'CANCELLED'] as const;

export interface ChallengeOutcomes {
  readonly total: number;
  /** Of the passed step-ups, those whose original request went out again; null when the portal does not say. */
  readonly resumed: number | null;
  readonly outcomes: readonly { readonly key: string; readonly n: number }[];
}

/**
 * Every step-up Contexa asked for in this demo, by outcome, as the portal counted them (teaser CHALLENGE_OUTCOMES,
 * forced runs left out); null when the portal has none. Nothing is counted here.
 */
export function challengeOutcomes(teasers: TeasersView | undefined): ChallengeOutcomes | null {
  const teaser = teasers?.teasers.find((item) => item.key === 'CHALLENGE_OUTCOMES');
  if (!teaser || teaser.missing) {
    return null;
  }
  const total = teaser.values['total'];
  const resumed = teaser.values['resumed'];
  const raw = teaser.values['outcomes'];
  if (typeof total !== 'number' || total === 0 || raw === null || typeof raw !== 'object') {
    return null;
  }
  const rank = (key: string) => {
    const index = (OUTCOME_ORDER as readonly string[]).indexOf(key);
    return index < 0 ? OUTCOME_ORDER.length : index;
  };
  const outcomes = Object.entries(raw as Readonly<Record<string, unknown>>)
    .filter((entry): entry is [string, number] => typeof entry[1] === 'number')
    .sort((left, right) => rank(left[0]) - rank(right[0]))
    .map(([key, n]) => ({ key, n }));
  return { total, resumed: typeof resumed === 'number' ? resumed : null, outcomes };
}

const EXISTING = ['A', 'B', 'C1', 'C2'] as const;

/**
 * A stored agent run's requests as its steps record them: how many it sent, how many all four existing controls
 * delivered, and how many Contexa delivered (the old 6-3 normal pair line, read from the same outcome codes).
 */
export function pairCounts(run: AgentRunView): {
  readonly requests: number;
  readonly existing: number;
  readonly delivered: number;
} {
  return {
    requests: run.steps.length,
    existing: run.steps.filter((step) => EXISTING.every((control) => step.outcomes[control]?.outcome === 'DELIVERED'))
      .length,
    delivered: run.steps.filter((step) => step.outcomes['D']?.outcome === 'DELIVERED').length,
  };
}
