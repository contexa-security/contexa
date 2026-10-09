import type { TFunction } from 'i18next';
import type { EngineReason, Fact } from '../api/types';

/**
 * Visitor wording built from structured codes only (plan 3.2): the evidence kinds the engine cited and the company
 * fact codes of a recorded scene. Anything else is shown as recorded; nothing here writes a reason of its own.
 */
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
