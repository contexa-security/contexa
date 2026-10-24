import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getJson, postJson } from './http';
import { useJourney } from './journey';
import { useLiveRun } from './queries';
import type { Localized, LiveRunView } from './types';

/**
 * docs/agent A7-3: the business agent group (화면설계 4절 AD-0 to AD-4). The case is the portal's agent case as defined
 * (agent-tasks), apart from the scenario catalog; a run's work, its steps and the confirmation come from the run's
 * own records.
 */

/** The main case of the agent group (DD-26): a scheduled run after the delegation ended. */
export const AGENT_CASE = 'T5';

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
}

export interface AgentRecorded {
  readonly runId: string;
  readonly startedAt: string | null;
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

export function useAgentCase(key: string) {
  return useQuery({
    queryKey: ['agent-case', key],
    queryFn: () => getJson<AgentCaseView>(`/api/agent-cases/${key}`),
    staleTime: 60_000,
    retry: false,
  });
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
