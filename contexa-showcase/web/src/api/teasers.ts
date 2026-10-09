import { useQuery } from '@tanstack/react-query';
import { getJson } from './http';

/**
 * The teaser cards' measured values and the facts the screens' sentences rest on (portal TeaserService). The card's
 * wording lives in the dictionary; each value here comes from the named stored record, and `holds` says whether that
 * record makes the card's sentence true, so the screen shows the approved fallback sentence otherwise.
 */
export type TeaserKey =
  | 'HOOK_TRY'
  | 'E1_RESULT_FACTS'
  | 'E1_REASON_MAILBOX'
  | 'E1_AFTER_RULES'
  | 'E2_RESULT_DIFF'
  | 'G_RULES_RESUME'
  | 'FOLLOW_LEARNED'
  | 'LEARN_WHY_TAUGHT'
  | 'G_HOW_LINES'
  | 'E1_PROMPT_ASYNC'
  | 'SYNC_WHEN_OBSERVATIONS'
  | 'LEARN_AFTER_FALSE_BLOCKS'
  | 'G_WHERE_C2'
  | 'BENCHMARK_CONCLUSIONS'
  | 'RISK_JUDGED_STOPPED'
  | 'CHALLENGE_OUTCOMES';

export interface TeaserSource {
  readonly kind: 'CASE_DEFINITION' | 'RUN' | 'MEASUREMENT' | 'TEMPLATE' | 'BENCHMARK' | 'CHALLENGES';
  /** The case keys, run ID, protocol ID, template ID or setting hash. */
  readonly ref: string;
}

export interface Teaser {
  readonly key: TeaserKey;
  readonly values: Readonly<Record<string, unknown>>;
  /** Whether the record makes the card's sentence true; null for a card that states no fact. */
  readonly holds: boolean | null;
  readonly source: TeaserSource | null;
  /** Why the values are empty (NO_HOOK, NO_TEMPLATE, NO_BENCHMARK, NO_RUN, NO_TEXTS); null otherwise. */
  readonly missing: string | null;
}

export interface TeasersView {
  readonly computedAt: string;
  readonly teasers: readonly Teaser[];
}

export function useTeasers() {
  return useQuery({
    queryKey: ['teasers'],
    queryFn: () => getJson<TeasersView>('/api/teasers'),
    staleTime: 60_000,
    retry: false,
  });
}
