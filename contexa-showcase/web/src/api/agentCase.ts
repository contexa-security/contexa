import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { getJson, postJson } from './http';
import { useJourney } from './journey';
import { useLiveConfig, useLiveRun } from './queries';
import { subjectOfSender, type Subject } from '../domain/subject';
import type { Localized, LiveRunView } from './types';

/**
 * docs/agent A7-3: the business agent group (화면설계 4절 AD-0 to AD-4). The case is the portal's agent case as defined
 * (agent-tasks), apart from the scenario catalog; a run's work, its steps and the confirmation come from the run's
 * own records.
 */

/** The main case of the agent group (DD-26): a scheduled run after the delegation ended. */
export const AGENT_CASE = 'T5';

/**
 * The keys of the cases the agent's track opens, the main case first (구현계획 NW-3): a visitor's run of any of them is a
 * run of the agent's track. Without the portal's list, the main case alone.
 */
export function useAgentCaseKeys(): readonly string[] {
  const config = useLiveConfig();
  const keys = (config.data?.agentCases ?? []).map((item) => item.key);
  return [AGENT_CASE, ...keys.filter((key) => key !== AGENT_CASE)];
}

/** The delegation as the case records it; its times are minutes from the run's company time. */
export interface AgentDelegation {
  readonly project: string;
  readonly purpose: string;
  readonly summary: Localized;
  readonly operations: readonly string[];
  readonly resources: readonly string[];
  readonly validFromMinutes: number | null;
  /** When it ends, from the work's company time (negative: it ended before the work). */
  readonly validUntilMinutes: number | null;
  readonly status: string;
  readonly approvalRequired: boolean;
  /** The quantity limit per request the delegation states; null when it states none. */
  readonly maxItemsPerRequest?: number | null;
}

/** One change of the delegation of the editable case, by the portal's fixed values; null keeps the case's own (AS-12). */
export interface DelegationChoice {
  readonly quantity: number | null;
  readonly period: string | null;
  readonly operations: string | null;
}

export const NO_CHOICE: DelegationChoice = { quantity: null, period: null, operations: null };

/** The query that names a choice to the portal: only the values that are set, nothing for no choice. */
export function choiceQuery(choice: DelegationChoice): string {
  const parts: string[] = [];
  if (choice.quantity !== null) {
    parts.push(`quantity=${choice.quantity}`);
  }
  if (choice.period !== null) {
    parts.push(`period=${choice.period}`);
  }
  if (choice.operations !== null) {
    parts.push(`operations=${choice.operations}`);
  }
  return parts.length === 0 ? '' : `?${parts.join('&')}`;
}

export interface AgentRecorded {
  readonly runId: string;
  readonly startedAt: string | null;
  /** How many operator recordings the case's definition has, counted by the portal (AS-5). */
  readonly runs: number;
  /** How many of them ended as this one did at control D. */
  readonly sameAsLatest: number;
}

export interface AgentCaseView {
  readonly key: string;
  readonly version: number;
  readonly title: Localized;
  readonly protagonist: string;
  readonly agentName: string;
  readonly agentTitle: Localized;
  readonly sender: string;
  readonly instruction: Localized;
  readonly delegation: AgentDelegation | null;
  readonly classification: string;
  /** The legitimate case of the same delegated work, within the delegation. */
  readonly normalPair: string | null;
  /** The latest operator recording of the case; null before any. */
  readonly recorded: AgentRecorded | null;
  readonly normalRecorded: AgentRecorded | null;
}

/** One step of an agent run: the tool that sent it, the five controls' outcomes and control D's decision. */
export interface AgentRunStep {
  readonly stepNo: number;
  readonly sentBy: 'AGENT_WORK' | 'SCRIPT';
  readonly tool: { readonly tool: string; readonly arguments: Readonly<Record<string, unknown>> } | null;
  readonly path: string;
  /** The company time the request went at. */
  readonly companyTime: string | null;
  readonly outcomes: Readonly<
    Record<
      string,
      { readonly outcome: string; readonly deliveredItems: number; readonly rule: string | null }
    >
  >;
  readonly decision?: {
    readonly final_action: string | null;
    readonly risk_score: number | null;
    readonly model_calls: number | null;
    readonly total_tokens: number | null;
  } | null;
}

/** The confirmation of a stored agent run, as the portal stored it. */
export interface AgentRunConfirmation {
  readonly stepNo: number;
  readonly confirmationId: string | null;
  readonly trigger: string | null;
  readonly expiresAt: string | null;
  readonly decision: 'APPROVE' | 'REJECT' | null;
  readonly reason: string | null;
  readonly askedAt: string | null;
  readonly decidedAt: string | null;
  readonly after: { readonly status: string | null; readonly authorizationId: string | null } | null;
  readonly resend: AgentResent | null;
  readonly reuse: AgentResent | null;
  readonly other: AgentResent | null;
}

export interface AgentResent {
  readonly httpStatus: number | null;
  readonly outcome: string | null;
  readonly deliveredItems: number;
  readonly ruleId: string | null;
}

/** What left at one control, as the portal scored the agent's work (AgentTaskProof.Control). */
export interface AgentProofControl {
  readonly documents: number;
  readonly items: number;
  readonly records: number;
  readonly changes: number;
  /** Protected documents, items, records and changes beyond what the given work needs. */
  readonly beyondNeed: number;
  /** The run step at which the control first answered other than with the data; null when never. */
  readonly firstStopStep: number | null;
  readonly firstStopOutcome: string | null;
}

/** The portal's scoring of an agent run (AgentTaskProof.Proof): the counts the result screen shows. */
export interface AgentProof {
  readonly attack: boolean;
  readonly deliverable: string | null;
  readonly finalAnswer: string | null;
  readonly stopReason: string;
  readonly completed: boolean;
  readonly mustNotLeave: readonly string[];
  /** What the given work needs of protected data; null when it needs none. */
  readonly workNeeds: number | null;
  readonly attempts: number;
  readonly toolCalls: number;
  /** The requests the work sent to the controls. */
  readonly sent: number;
  readonly controls: Readonly<Record<string, AgentProofControl>>;
}

/** What a burst did at control D, counted by the portal from the run's steps (AS-10, AS-13). */
export interface BurstSummary {
  readonly requests: number;
  readonly delivered: number;
  readonly refused: number;
  /** Refusals that only said the analysis was busy (they are not verdicts). */
  readonly busy: number;
  /** Requests that have a verdict of their own. */
  readonly withVerdict: number;
  readonly modelCalls: number;
  readonly firstStopStep: number | null;
  readonly deliveredAfterFirstStop: number;
}

export interface AgentRunView {
  readonly runId: string;
  readonly sender: string;
  readonly agentModel: string;
  readonly instruction: string;
  readonly stopReason: string;
  readonly failure: string | null;
  readonly finalAnswer: string | null;
  readonly startedAt: string;
  readonly finishedAt: string;
  /** The run's company time, which the case's delegation period counts from. */
  readonly companyTime: string | null;
  /** The portal's scoring of the work; null for a run stored before the scoring. */
  readonly proof?: AgentProof | null;
  /** The delegation this run executed: the case's own, or a visitor's copy with the change (AS-12); null when unknown. */
  readonly delegation?: AgentDelegation | null;
  /** The portal's counts of a burst run (AS-13); absent for any run that is no burst. */
  readonly burst?: BurstSummary;
  readonly steps: readonly AgentRunStep[];
  readonly confirmation: AgentRunConfirmation | null;
  readonly cost: {
    readonly agent: Readonly<Record<string, number>>;
    readonly decisions: readonly {
      readonly model: string;
      readonly calls: number;
      readonly total_tokens: number | null;
    }[];
  };
}

export function useAgentCase(key: string, choice: DelegationChoice = NO_CHOICE, enabled = true) {
  return useQuery({
    queryKey: ['agent-case', key, choice],
    queryFn: () => getJson<AgentCaseView>(`/api/agent-cases/${key}${choiceQuery(choice)}`),
    enabled,
    staleTime: 60_000,
    retry: false,
  });
}

/**
 * The delegation choice the address names for the case the screens follow (docs/agent Agent중심-화면 AS-12): the values of
 * the portal's lists only, and only for the one case whose delegation may be edited; otherwise no choice.
 *
 * @param passive true for a part of a screen whose screen has read it already: it sends no request of its own
 */
export function useDelegationChoice(caseKey: string, passive = false): DelegationChoice {
  const [params] = useSearchParams();
  const edit = useLiveConfig(!passive).data?.delegationEdit;
  if (edit === undefined || edit.case !== caseKey) {
    return NO_CHOICE;
  }
  const quantity = Number(params.get('quantity'));
  const period = params.get('period');
  const operations = params.get('operations');
  return {
    quantity: params.get('quantity') !== null && edit.quantities.includes(quantity) ? quantity : null,
    period: period !== null && edit.periods.includes(period) ? period : null,
    operations: operations !== null && edit.operations.includes(operations) ? operations : null,
  };
}

/**
 * The case the agent group's screens follow (docs/agent Agent중심-화면 AS-14), among the cases the portal opens to
 * visitors: the one the address names (the lab's link), else the one the visitor's live run is of, else the latest agent
 * run of the journey, else {@link AGENT_CASE}. A case the portal does not open is never followed.
 *
 * @param passive true for a part of a screen whose screen has read the case already: it reads what the screen asked
 *                for and sends no request of its own
 */
export function useAgentCaseKey(passive = false): string {
  const [params] = useSearchParams();
  // A part of a screen reads the case its screen already follows: a passive reading asks for nothing (a query that
  // answered "no run" is not asked again each time a part mounts, which would make the screen load and unload forever).
  const config = useLiveConfig(!passive).data;
  // the open cases, the one whose delegation a visitor may edit (AS-12) and the one a burst may be sent of (AS-13),
  // which are no entries of the list
  const open = [
    ...(config?.agentCases ?? []).map((found) => found.key),
    ...(config?.delegationEdit ? [config.delegationEdit.case] : []),
    ...(config?.burst ? [config.burst.case] : []),
  ];
  const live = useLiveRun(!passive);
  const journey = useJourney(!passive);
  const named = params.get('case');
  if (named !== null && open.includes(named)) {
    return named;
  }
  const going = live.data?.scenario;
  if (going !== undefined && open.includes(going)) {
    return going;
  }
  const earlier = [...(journey.data?.runs ?? [])].reverse().find((line) => open.includes(line.scenarioKey));
  return earlier?.scenarioKey ?? AGENT_CASE;
}

/**
 * Who sends the requests of the agent group's case, read from the case's own sender (docs/agent Agent중심-화면 AS-1);
 * none while the case is not read yet, so a screen never shows a guess.
 */
export function useAgentSubject(): Subject | undefined {
  const sender = useAgentCase(useAgentCaseKey(true)).data?.sender;
  return sender === undefined ? undefined : (subjectOfSender(sender) ?? undefined);
}

/**
 * A stored agent run's work; {@code version} (the live confirmation's stage) reads it again once the confirmation was
 * answered.
 */
export function useAgentRun(runId: string | null, version: string | null = null) {
  return useQuery({
    queryKey: ['agent-run', runId, version],
    queryFn: () => getJson<AgentRunView>(`/api/runs/${runId}/agent`),
    enabled: runId !== null,
    retry: false,
  });
}

/**
 * The visitor's run of the agent case: the live view while it is the portal's current run, else the latest completed
 * run of the case in the visitor's journey; null before the visitor sent it.
 */
export function useAgentTry(key: string) {
  const live = useLiveRun(true);
  const current: LiveRunView | null = live.data?.scenario === key ? live.data : null;
  const journey = useJourney(current === null);
  const storedId = current
    ? null
    : ([...(journey.data?.runs ?? [])]
        .reverse()
        .find((line) => line.scenarioKey === key && line.status === 'COMPLETED')?.runId ?? null);
  return {
    pending: live.isPending || (current === null && journey.isPending),
    live: current,
    runId: current?.runId ?? storedId,
    /** The run is the visitor's own (followed live or stored), not an operator's recording. */
    own: current !== null || storedId !== null,
  };
}

/** Answers the confirmation of the agent's request as the delegating employee. */
export function useAgentConfirmationAnswer() {
  const client = useQueryClient();
  return async (approve: boolean) => {
    const result = await postJson<LiveRunView>('/api/live/runs/current/agent-confirmation', { approve });
    const ok = result.status >= 200 && result.status < 300;
    if (ok && result.body) {
      client.setQueryData(['live-run'], result.body);
    }
    return ok;
  };
}
