/**
 * The bundles of the prompt the engine sent (e1-prompt, D-38): their names, the plain-words notes for the lines that
 * get one, and how the stored text is cut into the sections the server counts. A v19 prompt has the seven bundles of
 * the screen design; a v20 prompt has one bundle per dictionary block (W3-10).
 */
export type Layout = 'V19_SECTIONS' | 'V20_BLOCKS';
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
export interface PlainRule {
  readonly starts: string;
  readonly key: string;
}

/**
 * N-K5-1: the minimum action rules section of a v20 system prompt (W4-4; bundles from 2026.10.15-v20.17 on): the head
 * that says each rule names its floor, the rules P1 to P3 and the sentence on what is not unexplained. A rule is matched
 * on its whole line (its values and its floor), so a rule the host set otherwise (another resource class, count or
 * floor) gets no note and the words never state a value the line does not. The v19 prompts and the v20 prompts before
 * W4-4 state the elevated-risk boundary instead; the portal still keeps the texts of their runs, so its note stays.
 */
export const MINIMUM_ACTION_PLAIN: readonly PlainRule[] = [
  { starts: 'Minimum action rules (each names its floor,', key: 'gRules.plain.minimum' },
  {
    starts:
      'P1 MIN_P1_IDENTITY_DEVIATION: ResourceClass is SENSITIVE or CRITICAL and DeviationsFromBaseline names at least 2 of time, day, network and device as unexplained. Floor: CHALLENGE.',
    key: 'gRules.plain.minP1',
  },
  {
    starts:
      'P2 MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT: Action is EXPORT, ResourceClass is SENSITIVE or CRITICAL, and DeviationsFromBaseline names the device or the network as unexplained. Floor: CHALLENGE.',
    key: 'gRules.plain.minP2',
  },
  {
    starts:
      'P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no. Floor: ESCALATE (a verified user does not supply the missing record).',
    key: 'gRules.plain.minP3',
  },
  {
    starts:
      'A difference explained by a record, against a baseline that is not established, or not compared is not unexplained.',
    key: 'gRules.plain.unexplained',
  },
];
/** The title the v21 render gives the decision facts block (the portal counts it as DECISION_FACTS, SC-1). */
const V21_FACTS_BLOCK = 'RECORDS AND COMPARISONS';

/**
 * Whether the prompt the server counted was drawn by a v21 bundle: its user prompt has the v21 decision facts block.
 * The sections are the server's; the screen only reads their names.
 */
export function isV21Prompt(sections: readonly { readonly name: string }[] | undefined | null): boolean {
  return (sections ?? []).some((section) => section.name.startsWith(V21_FACTS_BLOCK));
}

/**
 * SC-7: the words of a block of a v21 prompt where they differ from v20: its rules state how the AI judges and no line
 * they always keep, and its decision facts block holds the records and comparisons without the core's conclusions.
 */
export function blockNameKey(block: string, v21: boolean): string {
  return v21 && block === 'DECISION_FACTS' ? 'prompt.blockV21.DECISION_FACTS' : `prompt.block.${block}`;
}

export function blockWhatKey(block: string, v21: boolean): string {
  return v21 && (block === 'RULES' || block === 'DECISION_FACTS')
    ? `prompt.blockWhatV21.${block}`
    : `prompt.blockWhat.${block}`;
}

/**
 * SC-7 (docs/showcase/프롬프트-v21-구현계획.md): the lines of a v21 system prompt that get a plain-words note. The v21
 * text states no decision rule: its mission, how it reads the evidence, the explanations it weighs, what each response
 * does and how it chooses one, and its honesty. A line is matched on how it begins, as for the other bundles.
 */
export const V21_RULES_PLAIN: readonly PlainRule[] = [
  { starts: 'Sign-in, permissions and fixed rules have already let this request through', key: 'gRules.plain.v21Mission' },
  { starts: '* An UNKNOWN fact is neither a match nor a mismatch', key: 'gRules.plain.v21Unknown' },
  { starts: "* An approval or a ticket records a person's earlier judgment", key: 'gRules.plain.v21Records' },
  { starts: '2. Weigh these explanations against every fact:', key: 'gRules.plain.v21Hypotheses' },
  { starts: "The account owner's records (assignment, duty, approvals, past work)", key: 'gRules.plain.v21OwnerRecords' },
  { starts: '3. Check each difference yourself', key: 'gRules.plain.v21Differences' },
  { starts: '4. Read what the data is', key: 'gRules.plain.v21Data' },
  { starts: 'ALLOW: the request goes on now.', key: 'gRules.plain.v21ALLOW' },
  { starts: 'CHALLENGE: the request waits until the account owner passes an extra check', key: 'gRules.plain.v21CHALLENGE' },
  { starts: 'ESCALATE: the facts here cannot settle the response', key: 'gRules.plain.v21ESCALATE' },
  // The line of v21.1 to v21.5, which recorded runs keep: it called ESCALATE a person's review (corrected in v21.6).
  { starts: 'ESCALATE: the request is held until a person reviews it.', key: 'gRules.plain.v21ESCALATEBefore216' },
  { starts: 'BLOCK: the account is stopped until it is released.', key: 'gRules.plain.v21BLOCK' },
  { starts: 'Choose the response from the explanation you judged most likely', key: 'gRules.plain.v21Choose' },
  { starts: '* Use only what the lines state.', key: 'gRules.plain.v21Honesty' },
];

export const PLAIN: Readonly<Record<Bundle, readonly PlainRule[]>> = {
  RULES: [
    { starts: 'ALLOW =', key: 'gRules.plain.ALLOW' },
    { starts: 'CHALLENGE =', key: 'gRules.plain.CHALLENGE' },
    { starts: 'ESCALATE =', key: 'gRules.plain.ESCALATE' },
    { starts: 'BLOCK =', key: 'gRules.plain.BLOCK' },
    { starts: 'Required elevated-risk boundary', key: 'gRules.plain.elevated' },
    ...MINIMUM_ACTION_PLAIN,
    ...V21_RULES_PLAIN,
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

/**
 * The blocks of a v20 prompt in the server's screen order: the rules, the five parts in the order the model reads them,
 * the folded past records and outside text, then the block the Layer2 second pass adds.
 */
export type Block =
  | 'RULES'
  | 'REQUEST'
  | 'SESSION'
  | 'USER_BASELINE'
  | 'DECISION_FACTS'
  | 'UNKNOWN'
  | 'PAST_RECORDS'
  | 'UNTRUSTED_TEXT'
  | 'SECOND_PASS';
export const BLOCKS: readonly Block[] = [
  'RULES',
  'REQUEST',
  'SESSION',
  'USER_BASELINE',
  'DECISION_FACTS',
  'UNKNOWN',
  'PAST_RECORDS',
  'UNTRUSTED_TEXT',
  'SECOND_PASS',
];

/**
 * The v20 lines that get a plain-words note: only where the note states what the line says. The system prompt is the
 * same text in both layouts, so the rules keep their notes.
 */
export const BLOCK_PLAIN: Readonly<Record<Block, readonly PlainRule[]>> = {
  RULES: PLAIN.RULES,
  REQUEST: [{ starts: 'Roles:', key: 'prompt.plain.roles' }],
  SESSION: [],
  USER_BASELINE: [{ starts: 'BaselineStatus: ESTABLISHED', key: 'prompt.plain.baseline' }],
  DECISION_FACTS: [
    { starts: 'PolicySatisfied: no — no approval', key: 'prompt.plain.approvalMissing' },
    { starts: 'AuthorizationEffect: ALLOW', key: 'prompt.plain.allowed' },
  ],
  UNKNOWN: [],
  PAST_RECORDS: [],
  UNTRUSTED_TEXT: [],
  SECOND_PASS: [],
};

interface BundleLines {
  readonly layout?: Layout;
  readonly bundles: readonly { readonly bundle: string; readonly lines: number }[];
}

/** The bundles the screen offers: a v20 prompt's blocks, with the second pass only when the prompt has one. */
export function shownBundles(lines: BundleLines): readonly (Bundle | Block)[] {
  if (lines.layout !== 'V20_BLOCKS') {
    return BUNDLES;
  }
  const secondPass = lines.bundles.find((entry) => entry.bundle === 'SECOND_PASS')?.lines ?? 0;
  return BLOCKS.filter((block) => block !== 'SECOND_PASS' || secondPass > 0);
}

/** A v20 decision fact line starts with its fact ID (`[F3] PolicySatisfied: …`, W3-13). */
const FACT_ID = /^\[F\d+\] /;

/** The original lines of a bundle that get a plain-words note, each with its note. */
export function plainLinesOf(
  layout: Layout | undefined,
  bundle: Bundle | Block,
  original: readonly string[],
): readonly (PlainRule & { readonly line: string })[] {
  const rules: readonly PlainRule[] =
    layout === 'V20_BLOCKS'
      ? (BLOCK_PLAIN[bundle as Block] ?? [])
      : (PLAIN[bundle as Bundle] ?? []);
  return original.flatMap((line) => {
    const fact = line.trim().replace(FACT_ID, '');
    const rule = rules.find((candidate) => fact.startsWith(candidate.starts));
    return rule ? [{ ...rule, line }] : [];
  });
}

/**
 * The call whose texts the server counts (the portal's anatomy reads the last call's prompt): a retry or a Layer2
 * call comes after the first, and only the last call of a second pass holds its SECOND PASS block.
 */
export function countedCall<T>(calls: readonly T[]): T | null {
  return calls.length > 0 ? (calls[calls.length - 1] ?? null) : null;
}

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
