import { GLOSSARY, type GlossaryGroup, type GlossaryTerm } from './terms';

/** Every term with its group, in the glossary's order. */
export const TERMS: readonly (GlossaryTerm & { readonly group: string })[] = GLOSSARY.flatMap((group) =>
  group.terms.map((term) => ({ ...term, group: group.id })),
);

/** The term an address names (`?term=`), or none when it names no term (ST-85). */
export function termOf(id: string | null): (GlossaryTerm & { readonly group: string }) | null {
  return TERMS.find((term) => term.id === id) ?? null;
}

/**
 * The groups with the terms a search finds: the words (any case) in the name in the screen's language, the official
 * English name, the short form or the definition.
 */
export function search(
  query: string,
  words: (term: GlossaryTerm) => readonly string[],
): readonly GlossaryGroup[] {
  const needle = query.trim().toLowerCase();
  if (needle === '') {
    return GLOSSARY;
  }
  return GLOSSARY.map((group) => ({
    ...group,
    terms: group.terms.filter((term) =>
      [term.en, ...words(term)].some((text) => text.toLowerCase().includes(needle)),
    ),
  })).filter((group) => group.terms.length > 0);
}
