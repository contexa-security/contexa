import type { IconName } from '../../components/Icon';
import { MINIMUM_ACTION_PLAIN, type PlainRule } from '../../components/inside/promptSections';

/**
 * The cards of the G-rules screen (RulesPage): the lines the rules always keep, each with the words of the rule line
 * it comes from (gRules.line.<key>). N-K5-1: the screen does not know a run's bundle before its original is opened, so
 * the cards follow the v20 rules the showcase sends, which state the minimum action rules and no elevated-risk boundary.
 */
export const G_RULES_CARDS: readonly { readonly key: string; readonly icon: IconName }[] = [
  { key: 'minimum', icon: 'lock' },
  { key: 'lowRisk', icon: 'check' },
  { key: 'least', icon: 'arrowRight' },
];

/**
 * The rule lines the G-rules screen notes in the original rules, by how the line begins: the four decisions, the
 * boundaries, the least disruptive choice and the minimum action rules section (N-K5-1). A line gets the note of the
 * first rule whose start it has. Only lines are matched, never counted or numbered: the numbers are the original
 * text's own lines. The elevated-risk boundary stays for the v19 and early v20 runs the portal still keeps.
 */
export const G_RULES_PLAIN: readonly PlainRule[] = [
  { starts: 'ALLOW =', key: 'gRules.plain.ALLOW' },
  { starts: 'CHALLENGE =', key: 'gRules.plain.CHALLENGE' },
  { starts: 'ESCALATE =', key: 'gRules.plain.ESCALATE' },
  { starts: 'BLOCK =', key: 'gRules.plain.BLOCK' },
  { starts: 'Required low-risk boundary', key: 'gRules.plain.lowRisk' },
  {
    starts:
      'Required covered-work boundary: choose ALLOW when AuthorizationEffect is ALLOW, PolicySatisfied is yes, DeviationsFromBaseline names no unexplained difference, and no other fact states an anomaly, a contradiction, a denial or a threat;',
    key: 'gRules.plain.coveredWork',
  },
  { starts: 'Required elevated-risk boundary', key: 'gRules.plain.elevated' },
  {
    starts:
      '6. Choose the least disruptive action justified by concrete evidence, never weaker than a minimum action rule that applies;',
    key: 'gRules.plain.leastFloor',
  },
  { starts: '6. Choose the least disruptive', key: 'gRules.plain.least' },
  ...MINIMUM_ACTION_PLAIN,
];
