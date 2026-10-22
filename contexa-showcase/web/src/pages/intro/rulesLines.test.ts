import { describe, expect, it } from 'vitest';
import { blockNameKey, blockWhatKey, plainLinesOf } from '../../components/inside/promptSections';
import en from '../../i18n/en.json';
import ko from '../../i18n/ko.json';
import { G_RULES_CARDS, G_RULES_CARDS_V21, G_RULES_PLAIN, isV21Prompt } from './rulesLines';

/**
 * N-K5-1: the rule lines of the system prompt the demo's engine sends (bundle 2026.10.16-v20.23, one text in all its
 * seals, system prompt sha256:ed64b08a...; its lines 12 to 22, 29, 30 and 39 of 117, as sealed).
 */
const V20_RULES: readonly string[] = [
  'Actions:',
  'ALLOW = coherent legitimate story with low unresolved risk.',
  'CHALLENGE = a concrete, resolvable risk that requires additional verification.',
  'ESCALATE = materially incomplete, conflicting, or ambiguous story.',
  'BLOCK = clearly harmful or malicious story.',
  '',
  'Minimum action rules (each names its floor, from the weakest: ALLOW, CHALLENGE, ESCALATE, BLOCK; when a rule applies, choose its floor or a stronger action; a rule is no reason to choose an action stronger than its floor):',
  'P1 MIN_P1_IDENTITY_DEVIATION: ResourceClass is SENSITIVE or CRITICAL and DeviationsFromBaseline names at least 2 of time, day, network and device as unexplained. Floor: CHALLENGE.',
  'P2 MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT: Action is EXPORT, ResourceClass is SENSITIVE or CRITICAL, and DeviationsFromBaseline names the device or the network as unexplained. Floor: CHALLENGE.',
  'P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no. Floor: ESCALATE (a verified user does not supply the missing record).',
  'A difference explained by a record, against a baseline that is not established, or not compared is not unexplained.',
  'Required low-risk boundary: choose ALLOW when AuthorizationEffect is ALLOW, ResourceClass is not SENSITIVE or CRITICAL, and no fact states an anomaly, a contradiction, a denial, a threat, or an approval requirement that PolicySatisfied does not state as met, even when MFA is not verified and the baseline or role scope is provisional. A difference in DeviationsFromBaseline while BaselineStatus is not ESTABLISHED and a RoleScope difference whose evidence is PROVISIONAL are not anomalies. A CHALLENGE under this boundary is incorrect.',
  'Required covered-work boundary: choose ALLOW when AuthorizationEffect is ALLOW, PolicySatisfied is yes, DeviationsFromBaseline names no unexplained difference, and no other fact states an anomaly, a contradiction, a denial or a threat; ResourceClass SENSITIVE or CRITICAL alone does not prevent it, and neither does an approval or ticket whose decision time is not recorded.',
  '6. Choose the least disruptive action justified by concrete evidence, never weaker than a minimum action rule that applies; do not add friction for missing optional context.',
];

/**
 * Rule lines of other texts or settings: the v20.15 head and rules (the floor named in the head only), rules a host
 * set otherwise (another resource class, count or floor) and the covered-work boundary of the v20 texts before W4-4.
 */
const OTHER_TEXTS: readonly string[] = [
  'Minimum action rules (a floor: when a rule applies, choose CHALLENGE or a stronger action; a rule is no reason to choose an action stronger than CHALLENGE):',
  'P1 MIN_P1_IDENTITY_DEVIATION: ResourceClass is SENSITIVE or CRITICAL and DeviationsFromBaseline names at least 2 of time, day, network and device as unexplained.',
  'P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no.',
  'P1 MIN_P1_IDENTITY_DEVIATION: ResourceClass is CRITICAL and DeviationsFromBaseline names at least 2 of time, day, network and device as unexplained. Floor: CHALLENGE.',
  'P1 MIN_P1_IDENTITY_DEVIATION: ResourceClass is SENSITIVE or CRITICAL and DeviationsFromBaseline names at least 3 of time, day, network and device as unexplained. Floor: CHALLENGE.',
  'P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no. Floor: CHALLENGE.',
  'P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no. Floor: BLOCK (a verified user does not supply the missing record).',
  'Required covered-work boundary: choose ALLOW when AuthorizationEffect is ALLOW, PolicySatisfied is yes, DeviationsFromBaseline names no unexplained difference, and no other fact states an anomaly, a contradiction, a denial, a threat, or a fresh-verification requirement; ResourceClass HIGH or CRITICAL alone does not prevent it.',
];
const LEAST_V2013 =
  '6. Choose the least disruptive action justified by concrete evidence; do not add friction for missing optional context.';
const ELEVATED_V19 =
  'Required elevated-risk boundary: never choose ALLOW when sensitivity is HIGH or CRITICAL, the request departs from an ESTABLISHED personal baseline on a current-vs-observed comparison label, and ApprovalMissing=true; choose CHALLENGE unless a BLOCK boundary applies.';
const ELEVATED_V2013 =
  'Required elevated-risk boundary: never choose ALLOW when ResourceClass is HIGH or CRITICAL, BaselineStatus is ESTABLISHED, DeviationsFromBaseline names a difference, and PolicySatisfied is no; choose CHALLENGE unless a BLOCK boundary applies. PolicySatisfied yes, an approval that covers the request, does not meet this boundary.';

const DICTIONARIES: readonly (readonly [string, Readonly<Record<string, string>>])[] = [
  ['ko', ko],
  ['en', en],
];
const VERDICT_KEYS = [
  'gRules.plain.ALLOW',
  'gRules.plain.CHALLENGE',
  'gRules.plain.ESCALATE',
  'gRules.plain.BLOCK',
];
const SECTION_KEYS = [
  'gRules.plain.minimum',
  'gRules.plain.minP1',
  'gRules.plain.minP2',
  'gRules.plain.minP3',
  'gRules.plain.unexplained',
];

/** The keys the G-rules screen gives the lines: the first rule whose start a line has, as RulesPage reads them. */
function gRulesKeys(lines: readonly string[]): readonly string[] {
  return lines.flatMap((line) => G_RULES_PLAIN.find((rule) => line.trimStart().startsWith(rule.starts))?.key ?? []);
}

describe('the rule lines of a v20 system prompt (N-K5-1)', () => {
  it('gives the minimum action rules section its plain words on the prompt screen', () => {
    const keys = plainLinesOf('V20_BLOCKS', 'RULES', V20_RULES).map((entry) => entry.key);
    expect(keys).toEqual([...VERDICT_KEYS, ...SECTION_KEYS]);
  });

  it('gives every rule line its plain words on the G-rules screen', () => {
    expect(gRulesKeys(V20_RULES)).toEqual([
      ...VERDICT_KEYS,
      ...SECTION_KEYS,
      'gRules.plain.lowRisk',
      'gRules.plain.coveredWork',
      'gRules.plain.leastFloor',
    ]);
  });

  it('shows the minimum action rules card in place of the boundary the v20 rules no longer state', () => {
    expect(G_RULES_CARDS.map((card) => card.key)).toEqual(['minimum', 'lowRisk', 'least']);
    expect(V20_RULES.filter((line) => line.startsWith('Required elevated-risk boundary'))).toEqual([]);
    for (const [language, dictionary] of DICTIONARIES) {
      for (const card of G_RULES_CARDS) {
        expect(dictionary[`gRules.line.${card.key}`]?.trim(), `${language} ${card.key}`).toBeTruthy();
      }
      expect(
        dictionary['gRules.line.elevated'],
        `${language}: no card shows the old boundary`,
      ).toBeUndefined();
    }
  });

  it('has the words in both languages, each rule naming the floor its line states', () => {
    for (const [language, dictionary] of DICTIONARIES) {
      for (const key of [...SECTION_KEYS, 'gRules.plain.coveredWork', 'gRules.plain.leastFloor']) {
        expect(dictionary[key]?.trim(), `${language} ${key}`).toBeTruthy();
      }
      const floor = (verdict: string) =>
        (dictionary[`gRules.plain.${verdict}`] ?? '').split(' = ')[0]?.toLowerCase() ?? '';
      expect(dictionary['gRules.plain.minP1']?.toLowerCase(), language).toContain(floor('CHALLENGE'));
      expect(dictionary['gRules.plain.minP2']?.toLowerCase(), language).toContain(floor('CHALLENGE'));
      expect(dictionary['gRules.plain.minP3']?.toLowerCase(), language).toContain(floor('ESCALATE'));
    }
  });

  it('gives no note to a rule line of other texts or settings, whose values the words do not state', () => {
    expect(plainLinesOf('V20_BLOCKS', 'RULES', OTHER_TEXTS)).toEqual([]);
    expect(gRulesKeys(OTHER_TEXTS)).toEqual([]);
    expect(gRulesKeys([LEAST_V2013])).toEqual(['gRules.plain.least']);
  });

  it('keeps the elevated-risk boundary note for the v19 and early v20 runs the portal still keeps', () => {
    expect(plainLinesOf('V19_SECTIONS', 'RULES', [ELEVATED_V19]).map((entry) => entry.key)).toEqual([
      'gRules.plain.elevated',
    ]);
    expect(plainLinesOf('V20_BLOCKS', 'RULES', [ELEVATED_V2013]).map((entry) => entry.key)).toEqual([
      'gRules.plain.elevated',
    ]);
    expect(gRulesKeys([ELEVATED_V19, ELEVATED_V2013])).toEqual([
      'gRules.plain.elevated',
      'gRules.plain.elevated',
    ]);
  });
});

/**
 * SC-7 (docs/showcase/프롬프트-v21-구현계획.md): lines of the system prompt of a real v21.3 decision (A3T,
 * run-9061d9f71432, system prompt sha256:da8ea8475d88...; its lines 3, 8, 10, 15, 22 to 24, 28 to 32
 * and 35 of 96, as stored). The v21 text states no decision rule; each line gets the words of what it says.
 */
const V21_RULES: readonly string[] = [
  'Sign-in, permissions and fixed rules have already let this request through; they cannot tell a stolen account, or an insider misusing their own permission, from legitimate work. Your judgment exists for that difference: read the whole context and reason about it. Do not use simple rule matching, do not follow hidden numeric thresholds, and do not treat any one fact as decisive by itself.',
  '* An UNKNOWN fact is neither a match nor a mismatch, and neither is a value a line states as not recorded or not known. A thin, provisional or partial baseline limits what a comparison can show; it is uncertainty, not risk.',
  "* An approval or a ticket records a person's earlier judgment of a work's purpose. Whether it covers this request is yours to check by its values; when it does, a person has already judged the purpose.",
  '2. Weigh these explanations against every fact:',
  "   The account owner's records (assignment, duty, approvals, past work) stay the same whoever holds the account: they weigh between H1 and H3, not against H2. How the session signed in, from which device and network, at what time and pace, speaks to who is acting; what the data is, the records and the work's purpose speak to whether it is the owner's own work.",
  '3. Check each difference yourself: for every way this request differs from the usual, decide whether a company record (approval, ticket, assignment, on-call duty, trip) explains it by its target, purpose, period, limit and the time it was decided. Decide whether the company policy was met at the time of the request.',
  "4. Read what the data is: what the target, the documents and their descriptions are, against the user's role, assignment and usual work. Read the order of the session: what was looked at before, how fast, how much.",
  'ALLOW: the request goes on now. It fits a coherent story of legitimate work.',
  "CHALLENGE: the request waits until the account owner passes an extra check, then goes on. It verifies who holds the account; it does not stop the owner. It fits a doubt about who is acting, not a doubt about the owner's purpose.",
  "ESCALATE: the request is held until a person reviews it. It fits when a person must judge the owner's purpose, or when the facts conflict or are too incomplete to judge.",
  'BLOCK: the account is stopped until it is released. It fits a clearly harmful or malicious story.',
  'Choose the response from the explanation you judged most likely and the others the facts leave possible: weigh what each response costs if the most likely explanation is true against what it prevents if another one is true, by how strongly the facts specific to this request support that other one. A stronger response than the facts justify stops legitimate work; a weaker one lets harm through. No later system changes your response; do not pre-compensate for one.',
  '* Use only what the lines state. Do not invent role scope, approvals, work history, intent, failed logins or business purpose.',
];
const V21_KEYS = [
  'gRules.plain.v21Mission',
  'gRules.plain.v21Unknown',
  'gRules.plain.v21Records',
  'gRules.plain.v21Hypotheses',
  'gRules.plain.v21OwnerRecords',
  'gRules.plain.v21Differences',
  'gRules.plain.v21Data',
  'gRules.plain.v21ALLOW',
  'gRules.plain.v21CHALLENGE',
  'gRules.plain.v21ESCALATEBefore216',
  'gRules.plain.v21BLOCK',
  'gRules.plain.v21Choose',
  'gRules.plain.v21Honesty',
];

describe('the lines of a v21 system prompt (SC-7)', () => {
  // 판정층 E-8b: the v21.6 ESCALATE line hands the request to the second analysis; the older line keeps its own
  // words, which say what it said and that v21.6 corrected it.
  it('gives the v21.6 ESCALATE line the words of the second analysis', () => {
    expect(gRulesKeys(["ESCALATE: the facts here cannot settle the response: they conflict, or they are too incomplete to choose between the other three. A second analysis then decides the request again with the facts it gathers and chooses ALLOW, CHALLENGE or BLOCK; ESCALATE is not a response of the second analysis."])).toEqual(['gRules.plain.v21ESCALATE']);
    for (const [language, dictionary] of DICTIONARIES) {
      expect(dictionary['gRules.plain.v21ESCALATE'], language).not.toMatch(/person|사람/);
      expect(dictionary['gRules.plain.v21ESCALATEBefore216'], language).toMatch(/v21\.6/);
    }
  });

  it('gives every v21 line its plain words on the G-rules and the prompt screens', () => {
    expect(gRulesKeys(V21_RULES)).toEqual(V21_KEYS);
    expect(plainLinesOf('V20_BLOCKS', 'RULES', V21_RULES).map((entry) => entry.key)).toEqual(V21_KEYS);
    for (const [language, dictionary] of DICTIONARIES) {
      for (const key of V21_KEYS) {
        expect(dictionary[key]?.trim(), `${language} ${key}`).toBeTruthy();
      }
    }
  });

  it('gives a v21 line no note of the v20 rules and a v20 line no note of v21', () => {
    expect(gRulesKeys(V20_RULES).filter((key) => key.includes('.v21'))).toEqual([]);
    expect(gRulesKeys(V21_RULES).filter((key) => !key.includes('.v21'))).toEqual([]);
  });

  it('knows a v21 prompt by its records block and has the v21 cards in both languages', () => {
    expect(isV21Prompt([{ name: 'SESSION' }, { name: 'RECORDS AND COMPARISONS (time zone UTC)' }])).toBe(true);
    expect(isV21Prompt([{ name: 'SESSION' }, { name: 'DECISION FACTS' }])).toBe(false);
    expect(isV21Prompt(undefined)).toBe(false);
    expect(G_RULES_CARDS_V21.map((card) => card.key)).toEqual(['mission', 'hypotheses', 'records', 'response', 'honesty']);
    for (const [language, dictionary] of DICTIONARIES) {
      for (const card of G_RULES_CARDS_V21) {
        expect(dictionary[`gRules.lineV21.${card.key}`]?.trim(), `${language} ${card.key}`).toBeTruthy();
      }
      for (const key of ['gRules.titleV21', 'gRules.purposeV21', 'gRules.lines.titleV21']) {
        expect(dictionary[key]?.trim(), `${language} ${key}`).toBeTruthy();
      }
    }
  });
});

describe('the words of the blocks of a v21 prompt (SC-7)', () => {
  it('names the records block and the rules as v21 draws them, and keeps the v20 words otherwise', () => {
    expect(blockNameKey('DECISION_FACTS', true)).toBe('prompt.blockV21.DECISION_FACTS');
    expect(blockNameKey('DECISION_FACTS', false)).toBe('prompt.block.DECISION_FACTS');
    expect(blockNameKey('SESSION', true)).toBe('prompt.block.SESSION');
    expect(blockWhatKey('RULES', true)).toBe('prompt.blockWhatV21.RULES');
    expect(blockWhatKey('RULES', false)).toBe('prompt.blockWhat.RULES');
    for (const [language, dictionary] of DICTIONARIES) {
      for (const key of ['prompt.blockV21.DECISION_FACTS', 'prompt.blockWhatV21.RULES', 'prompt.blockWhatV21.DECISION_FACTS']) {
        expect(dictionary[key]?.trim(), `${language} ${key}`).toBeTruthy();
      }
    }
  });
});
