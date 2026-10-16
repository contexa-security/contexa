import { describe, expect, it } from 'vitest';
import { plainLinesOf } from '../../components/inside/promptSections';
import en from '../../i18n/en.json';
import ko from '../../i18n/ko.json';
import { G_RULES_CARDS, G_RULES_PLAIN } from './rulesLines';

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
  return lines.flatMap((line) => G_RULES_PLAIN.find((rule) => line.startsWith(rule.starts))?.key ?? []);
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
