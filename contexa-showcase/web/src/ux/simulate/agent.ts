import type { TFunction } from 'i18next';
import type { AgentDelegation, AgentRunStep, AgentRunView } from '../../api/agentCase';
import { useLiveConfig } from '../../api/queries';
import type { Verdict } from '../../domain/verdict';

/** Control D's answer to an agent's request its delegating person must confirm first (docs/agent A5-2). */
export const CONFIRMATION_RULE = 'AGENT_CONFIRMATION_REQUIRED';

/** The main case of the agent group (권장 시작) and the order its cards are shown in (기획안 7.0 d-pick-agent). */
export const AGENT_MAIN = 'T5';
const AGENT_ORDER = ['T5', 'N1', 'M22A', 'M10A', 'M14A'];

export type AgentStep = 'review' | 'live' | 'result';

export function agentPath(key: string, step: AgentStep, search = ''): string {
  return `/simulate/agent/${encodeURIComponent(key)}/${step}${search}`;
}

/** The cards' order: the designed order first, any other case the portal opens after them. */
export function sortAgentKeys(keys: readonly string[]): readonly string[] {
  const rank = (key: string) => {
    const index = AGENT_ORDER.indexOf(key);
    return index === -1 ? AGENT_ORDER.length : index;
  };
  return [...keys].sort((a, b) => rank(a) - rank(b));
}

/**
 * The agent cases the portal opens to visitors (DEC-27): the listed ones, and the one whose delegation a visitor may
 * change (the policy simulator leads to it). A case the portal does not open is never followed.
 */
export function useAgentCases() {
  const config = useLiveConfig();
  const listed = sortAgentKeys((config.data?.agentCases ?? []).map((item) => item.key));
  const editable = config.data?.delegationEdit?.case ?? null;
  return {
    pending: config.isPending,
    listed,
    editable,
    opens: (key: string) => listed.includes(key) || key === editable,
    titleOf: (key: string) => config.data?.agentCases?.find((item) => item.key === key)?.title ?? null,
  };
}

/** A control's answer to one request of the agent, as a verdict; CONFIRM when control D asked the delegating person. */
export type AgentCell = Verdict | 'CONFIRM' | null;

/** One control's answer to one request: live (its layer) or stored (the run's outcomes). */
export interface AgentAnswer {
  readonly outcome: string;
  readonly ruleId?: string | null | undefined;
  readonly deliveredItems: number;
}

export function agentCell(
  layer: Pick<AgentAnswer, 'outcome' | 'ruleId'> | null | undefined,
  action: string | null = null,
): AgentCell {
  if (!layer) {
    return null;
  }
  if (layer.outcome === 'DELIVERED') {
    return 'ALLOW';
  }
  if (layer.outcome === 'REFUSED' && layer.ruleId === CONFIRMATION_RULE) {
    return 'CONFIRM';
  }
  if (['REFUSED', 'STOPPED', 'CUT', 'BROKEN'].includes(layer.outcome)) {
    return 'BLOCK';
  }
  if (action === 'ALLOW' || action === 'CHALLENGE' || action === 'ESCALATE' || action === 'BLOCK') {
    return action;
  }
  return layer.outcome === 'HELD' ? 'PENDING' : 'NONE';
}

/** A stored step's outcomes in the live layers' shape. */
export function storedLayers(step: AgentRunStep): Readonly<Record<string, AgentAnswer>> {
  return Object.fromEntries(
    Object.entries(step.outcomes).map(([control, result]) => [
      control,
      { outcome: result.outcome, ruleId: result.rule, deliveredItems: result.deliveredItems },
    ]),
  );
}

/** "7 days before" / "2 hours before" / "3 hours after" the agent's work, from minutes relative to it. */
export function offsetWords(t: TFunction, minutes: number): string {
  if (minutes === 0) {
    return t('ux.agent.period.at');
  }
  const size = Math.abs(minutes);
  const [count, unit] =
    size % 1440 === 0 ? [size / 1440, 'days'] : size % 60 === 0 ? [size / 60, 'hours'] : [size, 'minutes'];
  return t(`ux.agent.period.${minutes < 0 ? 'before' : 'after'}.${unit}`, { count, n: count });
}

export type DelegationState = 'active' | 'ended' | 'notYet' | 'revoked' | 'none';

/** Where the agent's work stands against its delegation: inside its period, after it ended, revoked, or no record. */
export function delegationState(delegation: AgentDelegation | null | undefined): DelegationState {
  if (!delegation) {
    return 'none';
  }
  if (delegation.status === 'REVOKED') {
    return 'revoked';
  }
  if (delegation.validUntilMinutes !== null && delegation.validUntilMinutes < 0) {
    return 'ended';
  }
  return delegation.validFromMinutes !== null && delegation.validFromMinutes > 0 ? 'notYet' : 'active';
}

/**
 * The delegation period's start, end and the agent's request on one line, as fractions of the line (0 to 1); null when
 * the delegation has no start or no end.
 */
export function periodMarks(
  delegation: AgentDelegation,
): { readonly start: number; readonly end: number; readonly now: number } | null {
  const fromMinutes = delegation.validFromMinutes;
  const untilMinutes = delegation.validUntilMinutes;
  if (fromMinutes === null || untilMinutes === null) {
    return null;
  }
  const from = Math.min(fromMinutes, 0);
  const to = Math.max(untilMinutes, 0);
  const span = to - from || 1;
  // A little room on either side so a mark at the edge is still seen.
  const at = (minutes: number) => 0.04 + ((minutes - from) / span) * 0.92;
  return { start: at(fromMinutes), end: at(untilMinutes), now: at(0) };
}

/** An operation of the agent's tools in the visitor's words; its code when the dictionary has none. */
export function operationWords(t: TFunction, operation: string | null | undefined): string {
  return operation ? t(`ux.agent.op.${operation}`, { defaultValue: operation }) : '…';
}

/** The first request control D did not answer with the data; null when it let every request through. */
export function firstStop(run: AgentRunView | null | undefined): AgentRunStep | null {
  const at = run?.proof?.controls.D?.firstStopStep ?? null;
  if (at !== null) {
    return run?.steps.find((step) => step.stepNo === at) ?? null;
  }
  return run?.steps.find((step) => agentCell(storedLayers(step).D) !== 'ALLOW') ?? null;
}

export type AgentConclusion =
  | 'passed'
  | 'confirmAsked'
  | 'confirmApproved'
  | 'confirmRejected'
  | 'stopped'
  | 'unfinished';

/**
 * The result's conclusion (F-6) from the portal's scoring of the run and the stored confirmation: Contexa let every
 * request through, asked the delegating person (and what they answered), or stopped the agent's request.
 */
export function agentConclusion(run: AgentRunView): AgentConclusion {
  const stop = firstStop(run);
  if (stop === null) {
    return run.proof?.completed === false ? 'unfinished' : 'passed';
  }
  if (stop.outcomes.D?.rule === CONFIRMATION_RULE) {
    const decision = run.confirmation?.decision ?? null;
    return decision === 'APPROVE' ? 'confirmApproved' : decision === 'REJECT' ? 'confirmRejected' : 'confirmAsked';
  }
  return 'stopped';
}

/** How the visitor's call reads against what Contexa did: both stop the agent's request, or both let it through. */
export function actualCall(run: AgentRunView): 'ALLOW' | 'BLOCK' {
  return firstStop(run) === null ? 'ALLOW' : 'BLOCK';
}

const CALL_KEY = 'ux.agent.call.';

/**
 * The visitor's call for an agent case the portal does not score (DEC-35): kept in this browser's session only, for
 * the result to show beside what happened. Storage may be unavailable; the call is then simply not shown.
 */
export function rememberCall(key: string, call: 'ALLOW' | 'BLOCK'): void {
  try {
    sessionStorage.setItem(CALL_KEY + key, call);
  } catch {
    // No storage in this browser: nothing to remember.
  }
}

export function rememberedCall(key: string): 'ALLOW' | 'BLOCK' | null {
  try {
    const value = sessionStorage.getItem(CALL_KEY + key);
    return value === 'ALLOW' || value === 'BLOCK' ? value : null;
  } catch {
    return null;
  }
}
