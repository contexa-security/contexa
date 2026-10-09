import { useUrlModal } from './useUrlModal';

/** Every term of the plain-words tables (words, words2), by the key of its dictionary entries. */
export const GLOSSARY = [
  'result',
  'stolenAccount',
  'usual',
  'noDecision',
  'falseBlock',
  'missed',
  'stopRate',
  'interval',
  'act',
  'detail',
  'session',
  'shadow',
  'permission',
  'sync',
  'async',
  'rules',
  'situation',
  'history',
  'prior',
  'identityCheck',
  'learnAdd',
  'workScope',
] as const;
export type GlossaryTerm = (typeof GLOSSARY)[number];

/** The glossary modal's name in the address (?modal=glossary). */
export const GLOSSARY_MODAL = 'glossary';

/** Opens the glossary, on a term when one is given. */
export function useGlossary() {
  const modal = useUrlModal(GLOSSARY_MODAL);
  return (term?: GlossaryTerm) => modal.show(term ? { term } : {});
}
