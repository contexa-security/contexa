import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { getJson, postJson } from './http';

/**
 * The lab's rule tightening (lab-rules, 7.6, H-10): the recorded cases, the values the rule controls run with, and the
 * rule classes deciding the cases again with the visitor's settings. Every count is the server's.
 */
export interface RuleSettings {
  readonly nightStartHour: number;
  readonly nightEndHour: number;
  readonly volumeLimit: number;
  readonly dormant: boolean;
  readonly external: boolean;
  readonly falseClaim: boolean;
  readonly approval: boolean;
  readonly ticket: boolean;
  readonly assigned: boolean;
  /** Null keeps the company's policy row. */
  readonly assignedLimit: number | null;
  readonly history: boolean;
}

export interface RuleDefaults {
  readonly nightStartHour: number;
  readonly nightEndHour: number;
  readonly volumeLimit: number;
  readonly assignedLimit: number;
  readonly dormantWindowDays: number;
  readonly historyWindowDays: number;
  readonly ruleVersion: string;
  /** The settings the rule controls run with, every switch on. */
  readonly settings: RuleSettings;
}

export interface RuleCase {
  readonly scenario: string;
  readonly classification: string;
  readonly title: Readonly<Record<string, string>>;
  readonly runId: string;
}

export interface RuleCasesView {
  readonly computedAt: string;
  readonly defaults: RuleDefaults | null;
  readonly cases: readonly RuleCase[];
  /** The earliest and the latest end of the cases' runs, the records' period. */
  readonly recordedFrom?: string | null;
  readonly recordedTo?: string | null;
}

/** How one approach handled the cases with a ground truth (portal RuleEvaluation.Tally). */
export interface RuleTally {
  readonly attacks: number;
  readonly attacksStopped: number;
  readonly normals: number;
  readonly normalsBlocked: number;
  /** Contexa only: normal work held for the identity check, not blocked. */
  readonly normalsChecked: number;
  readonly undecided: number;
}

export interface RuleChange {
  readonly scenario: string;
  readonly classification: string;
  readonly control: 'C1' | 'C2';
  readonly before: boolean | null;
  readonly now: boolean | null;
}

export interface RuleResult {
  readonly casesComputedAt: string;
  readonly settings: RuleSettings;
  readonly tallies: Readonly<Record<'C1' | 'C2' | 'D', RuleTally>>;
  readonly changed: readonly RuleChange[];
}

export function useRuleCasesView() {
  return useQuery({
    queryKey: ['rule-cases'],
    queryFn: () => getJson<RuleCasesView>('/api/rules/cases'),
    staleTime: 60_000,
  });
}

/** The cases decided again with the settings; the previous answer stays on screen while the next one comes. */
export function useRuleResult(settings: RuleSettings | null) {
  return useQuery({
    queryKey: ['rule-result', settings],
    queryFn: settings
      ? async () => {
          const answer = await postJson<RuleResult>('/api/rules/evaluate', settings);
          if (answer.status !== 200 || answer.body === null) {
            throw new Error(`The rule evaluation answered ${answer.status}`);
          }
          return answer.body;
        }
      : () => Promise.reject(new Error('No settings')),
    enabled: settings !== null,
    placeholderData: keepPreviousData,
    staleTime: Infinity,
    retry: false,
  });
}
