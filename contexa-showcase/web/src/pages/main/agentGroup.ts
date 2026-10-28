import type { useTranslation } from 'react-i18next';
import type { AgentDelegation, AgentRunStep, AgentRunView } from '../../api/agentCase';
import type { LiveLayer } from '../../api/types';
import type { ChipKind } from './mainCases';

type T = ReturnType<typeof useTranslation>['t'];

/** docs/agent A7-3: the engine's answer to an agent's request its delegating person must confirm first (A5-2). */
export const CONFIRMATION_RULE = 'AGENT_CONFIRMATION_REQUIRED';
/** The experience the agent group's call is stored under (the portal scores it by control D's outcome). */
export const AGENT_EXPERIENCE = 'E4';

/** Where the agent group's screens are. */
export const AGENT_PATHS = {
  request: '/agent/request',
  console: '/agent/console',
  reason: '/agent/reason',
  confirm: '/agent/confirm',
  burst: '/agent/burst',
} as const;

/** An offset in minutes from the work's company time in plain words: "7일 전", "2시간 전", "3시간 뒤". */
export function offsetWords(t: T, minutes: number): string {
  const after = minutes > 0;
  const size = Math.abs(minutes);
  const [unit, n] =
    size >= 1440 && size % 1440 === 0
      ? ['days', size / 1440]
      : size >= 60 && size % 60 === 0
        ? ['hours', size / 60]
        : ['minutes', size];
  return t(`main.agent.offset.${after ? 'after' : 'before'}.${unit}`, { count: n });
}

/** The delegation's period, from the work's company time: "작업 7일 전부터 작업 2시간 전까지". */
export function periodWords(t: T, delegation: AgentDelegation): string {
  if (delegation.status === 'REVOKED') {
    // the administrator withdrew it before the work (AS-12): its period no longer matters
    return t('main.agent.periodRevoked');
  }
  const from = delegation.validFromMinutes;
  const until = delegation.validUntilMinutes;
  if (from === null && until === null) {
    return t('main.agent.periodOpen');
  }
  if (until === null) {
    return t('main.agent.periodFrom', { from: offsetWords(t, from ?? 0) });
  }
  return t('main.agent.periodValue', { from: offsetWords(t, from ?? 0), until: offsetWords(t, until) });
}

/** The company operation each tool of the business agent sends (the portal's BusinessAgentTools). */
const OPERATION_OF_TOOL: Readonly<Record<string, string>> = {
  listProjects: 'PROJECT_LIST',
  listDocuments: 'DOCUMENT_LIST',
  readDocument: 'DOCUMENT_READ',
  downloadDocument: 'DOCUMENT_DOWNLOAD',
  deleteDocument: 'DOCUMENT_DELETE',
  exportDocuments: 'EXPORT',
  readCustomer: 'CUSTOMER_READ',
  grantRole: 'ROLE_GRANT',
};

/** The operation the step's tool sent; null for a step no tool sent or a tool this code does not know. */
export function requestOperation(step: AgentRunStep): string | null {
  return step.tool ? (OPERATION_OF_TOOL[step.tool.tool] ?? null) : null;
}

/** The resource the step's request names (its project, document or customer), else its address. */
export function requestTarget(step: AgentRunStep): string {
  const args = step.tool?.arguments ?? {};
  for (const name of ['projectKey', 'documentKey', 'customerKey']) {
    const value = args[name];
    if (typeof value === 'string' && value !== '') {
      return value;
    }
  }
  return step.path;
}

/** An operation's name; its code when the dictionary has none. */
export function operationName(t: T, exists: (key: string) => boolean, operation: string): string {
  const key = `main.agent.op.${operation}`;
  return exists(key) ? t(key) : operation;
}

/** The chip of a control's outcome of an agent's request: delivered, a confirmation asked, or refused. */
export function outcomeChip(
  outcome: string | null | undefined,
  rule: string | null | undefined,
): {
  readonly kind: ChipKind;
  readonly word: string;
} {
  if (outcome === 'DELIVERED') {
    return { kind: 'allow', word: 'DELIVERED' };
  }
  if (outcome === 'REFUSED' && rule === CONFIRMATION_RULE) {
    return { kind: 'auth', word: 'CONFIRM' };
  }
  if (outcome === 'REFUSED' || outcome === 'CUT') {
    return { kind: 'block', word: 'REFUSED' };
  }
  return { kind: 'wait', word: outcome ?? 'WAITING' };
}

/** The live layers of a step as the stored run's outcomes. */
export function layersOf(step: AgentRunStep): Readonly<Record<string, LiveLayer>> {
  return Object.fromEntries(
    Object.entries(step.outcomes).map(([control, result]) => [
      control,
      {
        outcome: result.outcome,
        httpStatus: null,
        deliveredItems: result.deliveredItems,
        elapsedMs: 0,
        ruleId: result.rule,
      } as LiveLayer,
    ]),
  );
}

/** The first step control D asked the delegating person to confirm; null when none. */
export function confirmedStep(run: AgentRunView | null | undefined): AgentRunStep | null {
  return run?.steps.find((step) => step.outcomes.D?.rule === CONFIRMATION_RULE) ?? null;
}

/** The first step control D refused or asked about; null when it let every request through. */
export function firstStop(run: AgentRunView | null | undefined): AgentRunStep | null {
  return (
    run?.steps.find((step) => step.outcomes.D !== undefined && step.outcomes.D.outcome !== 'DELIVERED') ??
    null
  );
}

/** The four existing approaches all delivered the step's request. */
export function existingAllPassed(step: AgentRunStep | null): boolean {
  return (
    step !== null &&
    ['A', 'B', 'C1', 'C2'].every((control) => step.outcomes[control]?.outcome === 'DELIVERED')
  );
}

/** A company time plus minutes, as an ISO instant; null without a time. */
export function plusMinutes(companyTime: string | null | undefined, minutes: number | null): string | null {
  if (!companyTime || minutes === null) {
    return null;
  }
  return new Date(new Date(companyTime).getTime() + minutes * 60_000).toISOString();
}
