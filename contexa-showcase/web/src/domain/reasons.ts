import type { TFunction } from 'i18next';
import type { EngineReason, Fact, Layer, Timing } from '../api/types';

/**
 * Visitor wording of the reasons behind each layer, built from structured codes only (plan 3.2): rule IDs and the
 * facts the rule looked at, the engine's canonical reason codes and evidence kinds, and company fact codes. The
 * engine's own free-text reasoning is never translated; it is shown as engine text in the evidence chain.
 */
const KNOWN_RULES = new Set([
  'C1-NIGHT',
  'C1-VOLUME',
  'C1-DORMANT',
  'C1-PASS',
  'C2-PASS',
  'C2-APPROVAL',
  'C2-TICKET-ONCALL',
  'C2-ASSIGNED',
  'C2-TICKET',
  'C2-HISTORY',
  'C2-ACCOUNT',
  'C2-NO-CONTEXT',
  'C2-EXTERNAL-NETWORK',
  'C2-FALSE-CLAIM',
  'C2-CHANGE-TICKET',
  'C2-NO-CHANGE-TICKET',
  'RBAC-NO-RULE',
]);

export const KNOWN_ENGINE_REASONS = new Set([
  'TRUSTED_SIGNAL_BLOCK',
  'CORROBORATED_ATTACK_BLOCK',
  'ALLOW_BASELINE_NO_RISK',
  'ALLOW_LIMITED_BASELINE_NO_RISK',
  'ALLOW_BASELINE_SAME_RESOURCE_HISTORY',
  'ALLOW_SAME_RESOURCE_HISTORY',
  'CHALLENGE_FRESH_VERIFICATION',
]);

const KNOWN_EVIDENCE = new Set([
  'baseline',
  'sensitivity',
  'authorization',
  'resource',
  'session',
  'device',
  'location',
  'rag',
  'threat',
  'approval',
  'delegation',
]);

const KNOWN_FACTS = new Set([
  'ASSIGNED',
  'NOT_ASSIGNED',
  'APPROVAL_COVERS',
  'NO_APPROVAL',
  'TICKET_COVERS',
  'NO_TICKET',
  'ON_CALL',
  'NOT_ON_CALL',
  'ACCESS_DAYS_LAST_30',
  'ITEMS',
  'NETWORK_OFFICE',
  'NETWORK_TRAVEL',
  'NETWORK_EXTERNAL',
  'CLAIM_CONFIRMED',
  'CLAIM_NOT_CONFIRMED',
]);

const NUMBER = new Intl.NumberFormat('en-US');

/** Counts read as 4,831 in both languages; other values are shown as recorded. */
function text(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }
  const raw = String(value);
  return /^\d+$/.test(raw) ? NUMBER.format(Number(raw)) : raw;
}

/** The reason line of a rule control's card. */
export function ruleReason(layer: Layer, t: TFunction): string {
  if (layer.control === 'A') {
    if (layer.outcome === 'DELIVERED') {
      return t('rule.A.pass');
    }
    if (!layer.ruleId) {
      return t('rule.A.blocked');
    }
  }
  const id = layer.ruleId;
  if (id === 'RBAC') {
    const role = text(layer.ruleFacts.role);
    return layer.outcome === 'DELIVERED' ? t('rule.RBAC.allow', { role }) : t('rule.RBAC.deny', { role });
  }
  if (id && KNOWN_RULES.has(id)) {
    return t(`rule.${id}`, { items: text(layer.ruleFacts.items) });
  }
  return t('rule.unknown');
}

/** The reason line of the Contexa card: the engine's own reason, localized only when it is a contract sentence. */
export function engineReasonLine(layer: Layer, reason: EngineReason | null, t: TFunction): string {
  if (layer.evidence.unresolved) {
    return t('reason.D.unresolved');
  }
  if (!layer.evidence.decisionId) {
    return layer.evidence.timing === 'STATIC_AUTHORIZATION' ? t('reason.D.static') : t('reason.D.notAnalysed');
  }
  if (reason?.canonical && KNOWN_ENGINE_REASONS.has(reason.canonical)) {
    return t(`engineReason.${reason.canonical}`);
  }
  return t('reason.D.engineText');
}

/** Evidence kinds the engine cited, in visitor words; unknown kinds are left out rather than guessed. */
export function evidenceKinds(reason: EngineReason | null, t: TFunction): string[] {
  if (!reason) {
    return [];
  }
  return reason.evidenceRefs.filter((ref) => KNOWN_EVIDENCE.has(ref)).map((ref) => t(`evidenceRef.${ref}`));
}

export function factLine(fact: Fact, t: TFunction): string | null {
  if (!KNOWN_FACTS.has(fact.code)) {
    return null;
  }
  return t(`fact.${fact.code}`, { value: text(fact.value) });
}

export function timingLine(timing: Timing, t: TFunction): string {
  return t(`timing.${timing}`);
}
