/**
 * The two rule controls of the demo, recomputed on the screen with the visitor's settings (docs/showcase/화면설계서.md
 * scene 4). The formulas are the server's own: ThresholdRules (C1) and ContextLookupRules (C2) of the plain workload.
 * With DEFAULT_SETTINGS they reproduce the decisions the rule controls recorded for every case; a test checks that on
 * the cases of real runs (E-3).
 */

export type Operation =
  | 'PROJECT_LIST'
  | 'DOCUMENT_READ'
  | 'DOCUMENT_DOWNLOAD'
  | 'EXPORT'
  | 'EXPORT_STREAM'
  | 'EXPORT_ASYNC'
  | 'CUSTOMER_READ'
  | 'ROLE_GRANT';

export interface RuleCaseStep {
  readonly stepNo: number;
  readonly operation: Operation;
  readonly companyTime: string;
  readonly c1Facts: Readonly<Record<string, unknown>>;
  readonly c1Outcome: string;
  readonly c1Rule: string | null;
  readonly c2Facts: Readonly<Record<string, unknown>>;
  readonly c2Outcome: string;
  readonly c2Rule: string | null;
  readonly contexaOutcome: string;
  readonly contexaVerdict: string;
}

export interface RuleCase {
  readonly scenario: string;
  readonly classification: 'THREAT' | 'NORMAL';
  readonly title: Readonly<Record<string, string>>;
  readonly runId: string;
  readonly finishedAt: string | null;
  readonly steps: readonly RuleCaseStep[];
}

export interface RuleCasesView {
  readonly computedAt: string;
  readonly cases: readonly RuleCase[];
}

/** What the visitor can tune; the defaults are the published configuration of the two rule controls. */
export interface RuleSettings {
  /** Night window for handing data out, in hours of company time; start equal to end means no night. */
  readonly nightStart: number;
  readonly nightEnd: number;
  /** Most items one export may hand out (C1-VOLUME). */
  readonly volumeLimit: number;
  /** Refuse project data when the requester had no access in the last 30 days (C1-DORMANT). */
  readonly dormant: boolean;
  /** Refuse a request from outside the company networks and registered trips (C2-EXTERNAL-NETWORK). */
  readonly external: boolean;
  /** Refuse an export whose named ticket does not cover it (C2-FALSE-CLAIM). */
  readonly falseClaim: boolean;
  /** Pass an export an approval covers (C2-APPROVAL). */
  readonly approval: boolean;
  /** Pass with a fitting ticket: with on-call duty for an export, alone for documents, customers and grants. */
  readonly ticket: boolean;
  /** Pass the assigned employee: exports up to the assigned limit, documents, the account manager's customers. */
  readonly assigned: boolean;
  /** Most items an assigned employee exports without approval (C2-ASSIGNED). */
  readonly assignedLimit: number;
  /** Pass a document of a project the requester worked on in the last 90 days (C2-HISTORY). */
  readonly history: boolean;
}

export const DEFAULT_SETTINGS: RuleSettings = {
  nightStart: 22,
  nightEnd: 6,
  volumeLimit: 500,
  dormant: true,
  external: true,
  falseClaim: true,
  approval: true,
  ticket: true,
  assigned: true,
  assignedLimit: 500,
  history: true,
};

export interface RuleDecision {
  readonly allowed: boolean;
  readonly rule: string;
}

const BULK: ReadonlySet<Operation> = new Set([
  'DOCUMENT_DOWNLOAD',
  'EXPORT',
  'EXPORT_STREAM',
  'EXPORT_ASYNC',
]);
const EXPORTS: ReadonlySet<Operation> = new Set(['EXPORT', 'EXPORT_STREAM', 'EXPORT_ASYNC']);

function deny(rule: string): RuleDecision {
  return { allowed: false, rule };
}

function allow(rule: string): RuleDecision {
  return { allowed: true, rule };
}

function minutesOf(companyTime: string): number {
  const time = new Date(companyTime);
  return time.getUTCHours() * 60 + time.getUTCMinutes();
}

export function isNight(companyTime: string, settings: RuleSettings): boolean {
  const now = minutesOf(companyTime);
  const start = settings.nightStart * 60;
  const end = settings.nightEnd * 60;
  if (start === end) {
    return false;
  }
  return start > end ? now >= start || now < end : now >= start && now < end;
}

function number(value: unknown): number | null {
  return typeof value === 'number' ? value : null;
}

function flag(value: unknown, key: string): boolean {
  return typeof value === 'object' && value !== null && (value as Record<string, unknown>)[key] === true;
}

function field(value: unknown, key: string): unknown {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>)[key] : undefined;
}

/**
 * The static role check runs before both rule controls, as in ControlAuthorizationManager: a request the role does not
 * permit is refused whatever the rules say, so no setting on the screen changes it.
 */
const RBAC = 'RBAC';

function refusedByRole(rule: string | null): boolean {
  return rule === RBAC;
}

/** C1, ThresholdRules: night hand-out, export volume, dormancy, in that order. */
export function thresholdRule(step: RuleCaseStep, settings: RuleSettings): RuleDecision {
  if (refusedByRole(step.c1Rule)) {
    return deny(RBAC);
  }
  const facts = step.c1Facts;
  if (BULK.has(step.operation) && isNight(step.companyTime, settings)) {
    return deny('C1-NIGHT');
  }
  const items = number(facts.items);
  if (EXPORTS.has(step.operation) && items !== null && items > settings.volumeLimit) {
    return deny('C1-VOLUME');
  }
  const accessDays = number(facts.accessDaysLast30);
  if (settings.dormant && accessDays !== null && accessDays === 0) {
    return deny('C1-DORMANT');
  }
  return allow('C1-PASS');
}

/** C2, ContextLookupRules: the business records that justify the request, by operation. */
export function recordRule(step: RuleCaseStep, settings: RuleSettings): RuleDecision {
  if (refusedByRole(step.c2Rule)) {
    return deny(RBAC);
  }
  const facts = step.c2Facts;
  const external = settings.external && field(facts.network, 'kind') === 'EXTERNAL';
  switch (step.operation) {
    case 'PROJECT_LIST':
      return allow('C2-PASS');
    case 'EXPORT':
    case 'EXPORT_STREAM':
    case 'EXPORT_ASYNC': {
      // ClaimCheck.confirmed() on the server: the named ticket exists and covers the request.
      const claimConfirmed = flag(facts.claim, 'exists') && flag(field(facts.claim, 'coverage'), 'covered');
      if (settings.falseClaim && facts.claim !== undefined && facts.claim !== null && !claimConfirmed) {
        return deny('C2-FALSE-CLAIM');
      }
      if (external) {
        return deny('C2-EXTERNAL-NETWORK');
      }
      if (settings.approval && flag(facts.approval, 'covered')) {
        return allow('C2-APPROVAL');
      }
      if (settings.ticket && flag(facts.ticket, 'covered') && flag(facts.oncall, 'onCall')) {
        return allow('C2-TICKET-ONCALL');
      }
      const items = number(facts.items) ?? 0;
      if (settings.assigned && flag(facts.assigned, 'assigned') && items <= settings.assignedLimit) {
        return allow('C2-ASSIGNED');
      }
      return deny('C2-NO-CONTEXT');
    }
    case 'DOCUMENT_READ':
    case 'DOCUMENT_DOWNLOAD': {
      if (external) {
        return deny('C2-EXTERNAL-NETWORK');
      }
      if (settings.assigned && flag(facts.assigned, 'assigned')) {
        return allow('C2-ASSIGNED');
      }
      if (settings.ticket && flag(facts.ticket, 'covered')) {
        return allow('C2-TICKET');
      }
      if (settings.history && (number(facts.accessDaysLast90) ?? 0) > 0) {
        return allow('C2-HISTORY');
      }
      return deny('C2-NO-CONTEXT');
    }
    case 'CUSTOMER_READ': {
      if (external) {
        return deny('C2-EXTERNAL-NETWORK');
      }
      if (settings.assigned && flag(facts.customer, 'owner')) {
        return allow('C2-ACCOUNT');
      }
      if (settings.ticket && flag(facts.ticket, 'covered')) {
        return allow('C2-TICKET');
      }
      return deny('C2-NO-CONTEXT');
    }
    case 'ROLE_GRANT': {
      if (external) {
        return deny('C2-EXTERNAL-NETWORK');
      }
      if (settings.ticket && flag(facts.ticket, 'covered')) {
        return allow('C2-CHANGE-TICKET');
      }
      return deny('C2-NO-CHANGE-TICKET');
    }
    default:
      return allow('C2-PASS');
  }
}

/** A case counts as stopped when any of its requests is refused, as in the runs themselves. */
export function stoppedByRules(rule: RuleCase, settings: RuleSettings): boolean {
  return rule.steps.some(
    (step) => !thresholdRule(step, settings).allowed || !recordRule(step, settings).allowed,
  );
}

export function stoppedByContexa(rule: RuleCase): boolean {
  return rule.steps.some(
    (step) => step.contexaOutcome !== 'DELIVERED' && step.contexaOutcome !== 'UNRESOLVED',
  );
}

export interface Score {
  /** Attacks with at least one request refused. */
  readonly attacksStopped: number;
  readonly attacks: number;
  /** Legitimate work with at least one request refused. */
  readonly workHalted: number;
  readonly work: number;
}

export function score(cases: readonly RuleCase[], stopped: (rule: RuleCase) => boolean): Score {
  const attacks = cases.filter((rule) => rule.classification === 'THREAT');
  const work = cases.filter((rule) => rule.classification === 'NORMAL');
  return {
    attacksStopped: attacks.filter(stopped).length,
    attacks: attacks.length,
    workHalted: work.filter(stopped).length,
    work: work.length,
  };
}

/**
 * Gate G-3 of the plan: the scene opens only when Contexa does better than the rules as published, stopping at least
 * as many attacks while halting fewer legitimate requests.
 */
export function contexaBetter(cases: readonly RuleCase[]): boolean {
  const rules = score(cases, (rule) => stoppedByRules(rule, DEFAULT_SETTINGS));
  const contexa = score(cases, stoppedByContexa);
  return (
    contexa.attacks > 0 &&
    contexa.attacksStopped >= rules.attacksStopped &&
    contexa.workHalted < rules.workHalted
  );
}
