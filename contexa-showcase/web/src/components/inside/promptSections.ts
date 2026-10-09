/**
 * The seven bundles of the prompt the engine sent (e1-prompt, D-38): their names, the plain-words notes for the
 * lines that get one, and how the stored text is cut into the sections the server counts.
 */
export type Bundle = 'RULES' | 'REQUEST' | 'IDENTITY' | 'USUAL' | 'HISTORY' | 'COMPANY' | 'UNKNOWN';
export const BUNDLES: readonly Bundle[] = [
  'RULES',
  'REQUEST',
  'IDENTITY',
  'USUAL',
  'HISTORY',
  'COMPANY',
  'UNKNOWN',
];

/**
 * The lines of the original that get a plain-words note, by how the line begins (a line with another value gets none).
 * Only lines are matched; nothing is counted or decided here.
 */
export const PLAIN: Readonly<Record<Bundle, readonly { readonly starts: string; readonly key: string }[]>> = {
  RULES: [
    { starts: 'ALLOW =', key: 'gRules.plain.ALLOW' },
    { starts: 'CHALLENGE =', key: 'gRules.plain.CHALLENGE' },
    { starts: 'ESCALATE =', key: 'gRules.plain.ESCALATE' },
    { starts: 'BLOCK =', key: 'gRules.plain.BLOCK' },
    { starts: 'Required elevated-risk boundary', key: 'gRules.plain.elevated' },
  ],
  REQUEST: [
    { starts: 'User is requesting', key: 'prompt.plain.requesting' },
    { starts: 'MfaVerified: true', key: 'prompt.plain.mfa' },
  ],
  IDENTITY: [
    { starts: 'EffectiveRoles:', key: 'prompt.plain.roles' },
    { starts: 'AuthorizationEffect: ALLOW', key: 'prompt.plain.allowed' },
  ],
  USUAL: [
    { starts: 'PersonalBaselineStatus: ESTABLISHED', key: 'prompt.plain.baseline' },
    { starts: 'ObservedScopeSummary:', key: 'prompt.plain.observed' },
    { starts: 'RoleScopeEvidenceState: PROVISIONAL', key: 'prompt.plain.scope' },
  ],
  HISTORY: [
    { starts: 'RelatedDocumentCount:', key: 'prompt.plain.related' },
    { starts: 'RagRelevance: SAME_RESOURCE', key: 'prompt.plain.sameResource' },
  ],
  COMPANY: [
    { starts: 'ApprovalRequired: true', key: 'prompt.plain.approvalRequired' },
    { starts: 'ApprovalMissing: true', key: 'prompt.plain.approvalMissing' },
    { starts: 'ApprovalStatus: NO_COVERING_APPROVAL', key: 'prompt.plain.noCovering' },
    { starts: 'ApprovalLineage:', key: 'prompt.plain.lineage' },
  ],
  UNKNOWN: [
    { starts: '- MissingKnowledgeDecisionLimit', key: 'prompt.plain.decisionLimit' },
    { starts: '- MissingKnowledgeWarning: Peer cohort', key: 'prompt.plain.noPeers' },
  ],
};

/** The lines without the blank ones at the end. */
export function trimEnd(lines: readonly string[]): readonly string[] {
  let end = lines.length;
  while (end > 0 && (lines[end - 1] ?? '').trim() === '') {
    end -= 1;
  }
  return lines.slice(0, end);
}

/** The user prompt cut at its "=== NAME ===" heads, each section with its own lines (the head included). */
export function sectionsOf(text: string | null): ReadonlyMap<string, readonly string[]> {
  const sections = new Map<string, string[]>();
  let current: string[] | null = null;
  for (const line of (text ?? '').split('\n')) {
    const head = /^=== (.+) ===$/.exec(line.trim());
    if (head?.[1]) {
      current = [line];
      sections.set(head[1], current);
    } else {
      current?.push(line);
    }
  }
  return sections;
}
