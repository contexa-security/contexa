import { describe, expect, it } from 'vitest';
import en from '../i18n/en.json';
import glossary from '../i18n/glossary.json';
import ko from '../i18n/ko.json';
import { GLOSSARY } from './glossary/terms';

/**
 * The wording of the new screens (UC-9, 기획안 9 · 10 · 12절, DEC-72): every `ux.` key in both languages, free of the
 * old words, questions and suggestions the wording dictionary bans, and the same keys in Korean and English. The
 * engine word families the new screens show as they are (the decision lines, reason codes, hypotheses, canonical
 * reasons, outcomes and verdicts) are held to the same words (DEC-84).
 */
const KO = ko as Record<string, string>;
const EN = en as Record<string, string>;
const DICTIONARY = { ko: KO, en: EN } as const;

interface Banned {
  readonly lang: 'ko' | 'en';
  readonly pattern: string;
  readonly use: string;
  readonly why: string;
  readonly except: readonly string[];
}

const BANNED = glossary.banned as readonly Banned[];
const HEADS = ['ux.', 'fact.label.', 'fact.meaning.', 'reasonCode.', 'reasonCodeV4.', 'hypothesis.', 'reason.canonical.',
  'outcome.', 'verdict.'] as const;
const uxKeys = (dictionary: Record<string, string>) =>
  Object.keys(dictionary).filter((key) => HEADS.some((head) => key.startsWith(head)));
/** The words a screen shows: the interpolation names (`{{judged}}`) are code, not words. */
const shown = (text: string) => text.replace(/\{\{[^}]*\}\}/g, '');

describe('the wording of the new screens', () => {
  it('holds the same keys in Korean and English', () => {
    expect(uxKeys(KO).sort()).toEqual(uxKeys(EN).sort());
  });

  it('names every old word after a term of the security glossary', () => {
    const ids = new Set(GLOSSARY.flatMap((group) => group.terms.map((term) => term.id)));
    for (const term of glossary.terms) {
      expect(ids.has(term.id), term.id).toBe(true);
      expect(term.old.length, term.id).toBeGreaterThan(0);
    }
  });

  it.each(BANNED.map((banned) => [`${banned.lang} /${banned.pattern}/ → ${banned.use} (${banned.why})`, banned] as const))(
    'uses no banned word: %s',
    (_, banned) => {
      const pattern = new RegExp(banned.pattern, 'u');
      const dictionary = DICTIONARY[banned.lang];
      const hits = uxKeys(dictionary)
        .filter((key) => !banned.except.some((prefix) => key.startsWith(prefix)))
        .filter((key) => pattern.test(shown(dictionary[key] ?? '')))
        .map((key) => `${key}: ${dictionary[key] ?? ''}`);
      expect(hits).toEqual([]);
    },
  );
});
