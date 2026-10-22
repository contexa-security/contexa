import type { DecisionAnatomyView } from '../../api/anatomy';
import type { Teaser, TeasersView } from '../../api/teasers';
import { VERDICTS, type Verdict } from '../../domain/verdict';

/** The nine steps every request passes, in order: the same steps and names as screen 3-2's figure (RO-11). */
export const STEPS = [
  'request',
  'usual',
  'company',
  'history',
  'prompt',
  'judgement',
  'decision',
  'followUp',
  'learning',
] as const;

export type Step = (typeof STEPS)[number];

/** A recorded action as a verdict the chips can show; anything else is "no judgment". */
export function verdictOf(action: string | null | undefined): Verdict {
  return action && action in VERDICTS ? (action as Verdict) : 'NONE';
}

/** Whether Contexa analysed the request itself: a judgment of its own, not an earlier one's or the app's refusal. */
export function analysed(view: DecisionAnatomyView): boolean {
  return view.interpretation.recorded.finalAction !== null;
}

/** The situation's right handling as its definition sets it: a request to stop, one to let through, or none set. */
export type Expected = 'stop' | 'pass' | 'none';

export function expectedOf(classification: string | null): Expected {
  return classification === 'THREAT' ? 'stop' : classification === 'NORMAL' ? 'pass' : 'none';
}

/**
 * The words of the server's score against the right handling (기획안 11.2): "right" means the judgment fell within
 * the handling the situation counts as right (F-5), so it reads "stopped as it should be" or "let through as it should
 * be", never "the same as Contexa"; a miss and a blocked work say which kind of wrong they are.
 */
export function resultKey(result: string, expected: Expected): string {
  switch (result) {
    case 'RIGHT':
      return expected === 'pass' ? 'detail.r7.result.rightPass' : 'detail.r7.result.rightStop';
    case 'MISSED':
    case 'FALSE_BLOCK':
    case 'UNRESOLVED':
    case 'NO_DECISION':
      return `detail.r7.result.${result}`;
    default:
      return 'detail.r7.result.NOT_SCORED';
  }
}

/**
 * The identity checks' outcomes in the order they are read (portal LiveRun, ControlSession): passed, the code went to a
 * mailbox the requester does not have, abandoned, timed out, the wrong code three times, cancelled; any other outcome
 * the server names (a failed automatic answer's own words) comes after them.
 */
const OUTCOME_ORDER = [
  'ANSWERED',
  'NO_MAILBOX',
  'ABANDONED',
  'EXPIRED',
  'WRONG_CODE_LIMIT',
  'CANCELLED',
] as const;

export interface ChallengeOutcomes {
  readonly total: number;
  /** Of the passed checks, those whose original request went out again (the work went on). */
  readonly resumed: number | null;
  readonly outcomes: readonly { readonly key: string; readonly n: number }[];
}

/**
 * The outcomes of every identity check Contexa asked for in this demo (forced runs left out), as the portal counted
 * them (teaser CHALLENGE_OUTCOMES); null when the server has none. Nothing is counted here.
 */
export function challengeOutcomes(teasers: TeasersView | undefined): ChallengeOutcomes | null {
  const teaser: Teaser | undefined = teasers?.teasers.find((item) => item.key === 'CHALLENGE_OUTCOMES');
  if (!teaser || teaser.missing) {
    return null;
  }
  const total = teaser.values['total'];
  const resumed = teaser.values['resumed'];
  const raw = teaser.values['outcomes'];
  if (typeof total !== 'number' || total === 0 || raw === null || typeof raw !== 'object') {
    return null;
  }
  const entries = Object.entries(raw as Readonly<Record<string, unknown>>).filter(
    (entry): entry is [string, number] => typeof entry[1] === 'number',
  );
  const rank = (key: string) => {
    const index = (OUTCOME_ORDER as readonly string[]).indexOf(key);
    return index < 0 ? OUTCOME_ORDER.length : index;
  };
  const outcomes = [...entries]
    .sort((left, right) => rank(left[0]) - rank(right[0]))
    .map(([key, n]) => ({ key, n }));
  return { total, resumed: typeof resumed === 'number' ? resumed : null, outcomes };
}

/** Whether an identity check outcome has words of its own; any other is shown as "other" with its recorded name. */
export function knownOutcome(key: string): boolean {
  return (OUTCOME_ORDER as readonly string[]).includes(key);
}

/**
 * The plain words of a rule line: the tab's own words where the dictionary has them, else the published rules screen's
 * words (the v21 lines have only those).
 */
export function ruleKey(key: string, exists: (key: string) => boolean): string {
  const own = key.replace(/^gRules\.plain\./, 'detail.r7.rule.');
  return exists(own) ? own : key;
}
