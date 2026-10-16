import type {
  FactBlock,
  FactSource,
  InspectionCheck,
  OtherBundleView,
  PromptFact,
  QualityRibbonView,
  RunFacts,
  RunQuality,
} from '../../api/promptQuality';
import { plainLinesOf } from '../inside/promptSections';

/**
 * The words of the prompt trust parts (screen design reinforcement 2, U-1): the five source grades, the v20 blocks in
 * the order the AI reads them, the dictionary's entry names that get plain words, and which fact a failing check
 * points to. Only names and lines are matched here; every count is the server's.
 */
export const FACT_SOURCES: readonly FactSource[] = ['HOST', 'LEARNED', 'COMPUTED', 'INFERRED', 'UNTRUSTED'];

/** The five parts in the order the AI reads them (the rules' judgment procedure, plan 6.3). */
export const CHUNKS: readonly FactBlock[] = ['REQUEST', 'SESSION', 'USER_BASELINE', 'DECISION_FACTS', 'UNKNOWN'];

/** The parts folded under the five; the second pass only when the prompt has one. */
export const FOLDS: readonly FactBlock[] = ['PAST_RECORDS', 'UNTRUSTED_TEXT', 'SECOND_PASS'];

/** Every entry of the v20 dictionary (core SecurityDecisionPromptDictionary), numbered entries by their stem. */
export const FACT_LABELS = [
  'Evidence',
  'BaselineStatus',
  'UsualHours',
  'UsualDays',
  'UsualNetworks',
  'UsualDevices',
  'UsualLoginMethods',
  'UsualTargets',
  'UsualActions',
  'UsualResourceClass',
  'UsualExportSize',
  'UsualRequestRate',
  'UsualSessionLength',
  'UsualPrivilegedActions',
  'SeasonalPattern',
  'KnownRareTasks',
  'WorkProfile',
  'PeerReference',
  'SessionAge',
  'LoginMethod',
  'ChallengeVerified',
  'RecentMfaElsewhere',
  'FailedLogins',
  'MfaFailures',
  'RequestsInSession',
  'RecentRequests',
  'ConcurrentSessions',
  'PasswordAge',
  'RecentSensitiveAccess',
  'RecentDenied',
  'Subject',
  'Roles',
  'Permissions',
  'Time',
  'Action',
  'Target',
  'Size',
  'ResourceClass',
  'Network',
  'Device',
  'DeviationsFromBaseline',
  'SameAsBaseline',
  'Policy',
  'PolicySatisfied',
  'Approval',
  'Assignment',
  'Ticket',
  'OnCall',
  'Travel',
  'RepeatInSession',
  'RoleScope',
  'RecentPermissionChanges',
  'TemporaryElevation',
  'AuthorizationEffect',
  'DataConflicts',
  'Movement',
  'SessionDeviceChange',
  'SessionNetworkChange',
  'ClientSignals',
  'BlockedUser',
  'BreakGlass',
  'PeerCohort',
  'Delegation',
  'ThreatMatch',
  'PastRecordsState',
  'PastRecordCounts',
  'PastRecord',
  'PastDeniedDecision',
  'SupportingCases',
  'ValidatedCases',
  'Coverage',
  'Unknown',
  'UntrustedText',
  'FirstPassVerdict',
  'NewlyKnown',
  'NewPastRecord',
] as const;
export type FactLabel = (typeof FACT_LABELS)[number];

/** The entries drawn once per item, their label the stem and the item's number (PastRecord1, UntrustedText2). */
const NUMBERED: readonly FactLabel[] = ['PastRecord', 'PastDeniedDecision', 'UntrustedText', 'NewPastRecord'];

/** The dictionary key of a line's label: its entry, or 'other' for a label the dictionary does not list. */
export function factKey(label: string): FactLabel | 'other' {
  if ((FACT_LABELS as readonly string[]).includes(label)) {
    return label as FactLabel;
  }
  return NUMBERED.find((stem) => label.startsWith(stem) && /^\d+$/.test(label.slice(stem.length))) ?? 'other';
}

/** The plain words W3-10 gave a v20 line (promptSections BLOCK_PLAIN), for the fact on that line; null otherwise. */
export function factNoteKey(block: FactBlock, fact: PromptFact): string | null {
  return plainLinesOf('V20_BLOCKS', block, [`${fact.label}: ${fact.value}`])[0]?.key ?? null;
}

/** A grade name as the source chip shows it; null for a name that is not one of the five. */
export function sourceOf(grade: string): FactSource | null {
  return (FACT_SOURCES as readonly string[]).includes(grade) ? (grade as FactSource) : null;
}

/** The sources a part's facts state, each once, in the order the facts state them. */
export function sourcesOf(facts: readonly PromptFact[]): readonly (FactSource | null)[] {
  return facts.reduce<(FactSource | null)[]>(
    (seen, fact) => (seen.includes(fact.source) ? seen : [...seen, fact.source]),
    [],
  );
}

/** The facts of one block as the server gave them; none when the server gave the block no facts. */
export function factsOf(facts: RunFacts | null, block: FactBlock): readonly PromptFact[] {
  return facts?.blocks.find((entry) => entry.block === block)?.facts ?? [];
}

/** The block a prompt line belongs to, among the blocks the server gave. */
export function blockOfLine(facts: RunFacts, line: number): FactBlock | null {
  return facts.blocks.find((entry) => entry.facts.some((fact) => fact.line === line))?.block ?? null;
}

/** The page address of a fact card, by the prompt line it shows. */
export function factAnchor(line: number): string {
  return `fact-line-${line}`;
}

/** The fact a reason code cites, found among the facts the AI received by its fact ID. */
export function citedFact(
  facts: RunFacts | null,
  factId: string | null,
): { readonly fact: PromptFact; readonly block: FactBlock } | null {
  if (!facts?.available || factId === null) {
    return null;
  }
  for (const entry of facts.blocks) {
    const fact = entry.facts.find((candidate) => candidate.factId === factId);
    if (fact) {
      return { fact, block: entry.block };
    }
  }
  return null;
}

/** Whether the screen offers the other-bundle comparison: only when the server found a run under the other bundle. */
export function compareOffered(view: OtherBundleView | null | undefined): boolean {
  return view?.available === true && view.current !== null && view.other !== null;
}

/** The checks of the official inspector v2 (core verification.inspection), for their plain names. */
export const INSPECTION_CHECKS = [
  'SEAL_INTEGRITY',
  'DICTIONARY_CONTRACT',
  'FACT_ACCURACY',
  'DECISION_FACT_MATCH',
  'SAME_FACT',
  'UNKNOWN_DECLARED',
  'PAST_RECORD_NOTATION',
  'REASON_MATCH',
  'SOURCE_TRUTH',
] as const;

/** The inspection verdicts (core PromptInspectionVerdict). */
export const INSPECTION_VERDICTS = ['PASS', 'FAIL', 'INCOMPLETE', 'NOT_APPLICABLE', 'ERROR'] as const;

/** The checks with a mismatch first, each group in the server's order (U-4: failed checks on top). */
export function failuresFirst(checks: readonly InspectionCheck[]): readonly InspectionCheck[] {
  return [...checks.filter((check) => check.mismatched > 0), ...checks.filter((check) => check.mismatched <= 0)];
}

/** The ribbon's items that can fail; 'unknown' is stated as it is. */
export type RibbonItem = 'source' | 'accuracy' | 'contradictions';
export const RIBBON_ITEMS: readonly RibbonItem[] = ['source', 'accuracy', 'contradictions'];

/**
 * Whether each item holds, read from the server's own pair of counts (no count is worked out here); null while the
 * seal has no inspection yet, for the items the inspection gives.
 */
export function ribbonHolds(ribbon: QualityRibbonView): Readonly<Record<RibbonItem, boolean | null>> {
  return {
    source: ribbon.withSource === ribbon.facts,
    accuracy: ribbon.factAccuracy === null ? null : ribbon.factAccuracy.matched === ribbon.factAccuracy.total,
    contradictions: ribbon.contradictions === null ? null : ribbon.contradictions === 0,
  };
}

/** The checks whose mismatches a ribbon item stands for. */
const ITEM_CHECKS: Readonly<Record<Exclude<RibbonItem, 'source'>, readonly string[]>> = {
  accuracy: ['FACT_ACCURACY', 'DECISION_FACT_MATCH', 'SOURCE_TRUTH'],
  contradictions: ['SAME_FACT'],
};

/** The prompt line of the first fact behind each item, for a failing item to lead to its fact card. */
export function ribbonLines(
  quality: RunQuality | null,
  facts: RunFacts | null,
): Readonly<Record<RibbonItem, number | null>> {
  const firstMismatch = (codes: readonly string[]): number | null =>
    quality?.inspection?.checks
      .filter((check) => codes.includes(check.code))
      .flatMap((check) => check.mismatches)
      .find((mismatch) => mismatch.line !== null)?.line ?? null;
  return {
    source: facts?.blocks.flatMap((entry) => entry.facts).find((fact) => fact.source === null)?.line ?? null,
    accuracy: firstMismatch(ITEM_CHECKS.accuracy),
    contradictions: firstMismatch(ITEM_CHECKS.contradictions),
  };
}
