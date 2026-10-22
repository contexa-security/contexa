import { useUrlModal } from './useUrlModal';

/**
 * The glossary's groups and terms, in the order of the redesign's word tables (화면재편-기획안 11절): the five security
 * approaches, results and judgments, what Contexa looks at, the demo and its numbers, then the words of the judgment
 * record checks. Each term's words are space.r7.glossary.{id}.term / .plain, and .industry where the field has its own
 * name for it (said once, in parentheses on the screens).
 */
export const GLOSSARY_GROUPS = [
  {
    id: 'approaches',
    terms: ['waf', 'access', 'limits', 'approval', 'contexa', 'session', 'permission', 'lab'],
  },
  {
    id: 'results',
    terms: [
      'result',
      'judgment',
      'pass',
      'identityCheck',
      'hold',
      'block',
      'expected',
      'rightStop',
      'rightPass',
      'missed',
      'falseBlock',
      'partly',
      'noDecision',
      'sync',
      'async',
    ],
  },
  {
    id: 'sees',
    terms: [
      'usual',
      'workRecord',
      'learned',
      'learnAdd',
      'workScope',
      'reason',
      'hardLimit',
      'rules',
      'prompt',
      'llm',
      'history',
      'prior',
      'original',
    ],
  },
  {
    id: 'demo',
    terms: [
      'part',
      'situation',
      'stolenAccount',
      'realUser',
      'sourceBadge',
      'sent',
      'export',
      'resend',
      'unblock',
      'shadow',
      'detail',
      'stopNone',
      'stopEnd',
      'normalPass',
      'stopRate',
      'interval',
      'preliminary',
    ],
  },
  {
    id: 'checks',
    terms: [
      'fact',
      'factSource',
      'reasonCode',
      'seal',
      'token',
      'riskScore',
      'delivery',
      'reaction',
      'invariance',
      'injection',
    ],
  },
] as const;

export type GlossaryTerm = (typeof GLOSSARY_GROUPS)[number]['terms'][number];

/** Every term of the glossary, group by group. */
export const GLOSSARY: readonly GlossaryTerm[] = GLOSSARY_GROUPS.flatMap((group) => group.terms);

/** The dictionary key of one of a term's words. */
export function glossaryKey(term: GlossaryTerm, part: 'term' | 'plain' | 'industry'): string {
  return `space.r7.glossary.${term}.${part}`;
}

/** The glossary modal's name in the address (?modal=glossary). */
export const GLOSSARY_MODAL = 'glossary';

/** Opens the glossary, on a term when one is given. */
export function useGlossary() {
  const modal = useUrlModal(GLOSSARY_MODAL, ['term']);
  return (term?: GlossaryTerm) => modal.show(term ? { term } : {});
}
