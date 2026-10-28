import { useQuery } from '@tanstack/react-query';
import { choiceQuery, NO_CHOICE, type AgentCaseView, type AgentRunView, type DelegationChoice } from './agentCase';
import { getJson } from './http';
import type { DelegationEdit, Localized } from './types';

/**
 * docs/agent Agent중심-화면 AC-4a: the agent menu, a finite table of cases and the paths an agent sends on. A daily job
 * runs each combination with the real engine and the portal keeps the run; the screens read the stored answer, so
 * choosing a combination calls no model.
 */

/** The three paths, in the order the portal lists them. */
export type MenuPath = 'OAUTH2_DELEGATED' | 'OAUTH2_AGENT' | 'SESSION';

export interface AgentMenuCase {
  readonly key: string;
  readonly title: Localized;
}

/** One stored answer of the table: when it ran and whether it is old or ran another definition of the case. */
export interface AgentMenuItem {
  readonly caseKey: string;
  readonly path: string;
  /** The delegation choice of the editable case's combination; null for a case without one (AC-4b). */
  readonly choice: DelegationChoice | null;
  readonly ranAt: string;
  readonly stale: boolean;
}

export interface AgentMenuListing {
  readonly cases: readonly AgentMenuCase[];
  readonly paths: readonly string[];
  readonly items: readonly AgentMenuItem[];
  /** The editable case and the values a visitor may choose; null while the portal has none. */
  readonly delegationEdit?: DelegationEdit | null;
}

export interface AgentMenuAnswer {
  readonly caseKey: string;
  readonly path: string;
  readonly choice?: DelegationChoice | null;
  readonly ranAt: string;
  readonly stale: boolean;
  readonly caseView: AgentCaseView;
  readonly run: AgentRunView;
}

/** The table; an error (a portal without the menu) leaves the screen without it. */
export function useAgentMenu() {
  return useQuery({
    queryKey: ['agent-menu'],
    queryFn: () => getJson<AgentMenuListing>('/api/agent-menu'),
    staleTime: 60_000,
    retry: false,
  });
}

/** One combination's stored answer; a 404 means the daily job has not stored one yet. */
export function useAgentMenuAnswer(
  caseKey: string | null,
  path: string | null,
  choice: DelegationChoice = NO_CHOICE,
) {
  return useQuery({
    queryKey: ['agent-menu', caseKey, path, choice],
    queryFn: () => getJson<AgentMenuAnswer>(`/api/agent-menu/${caseKey}/${path}${choiceQuery(choice)}`),
    enabled: caseKey !== null && path !== null,
    staleTime: 60_000,
    retry: false,
  });
}
