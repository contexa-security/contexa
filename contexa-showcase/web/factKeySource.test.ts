import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { FACT_LABELS } from './src/ux/runs/factKey';

/** The core's decision prompt dictionary and output contracts, read as the source of the entry names and the codes. */
const CORE = '../../contexa-core/src/main/java/io/contexa/contexacore/autonomous/tiered/prompt';

const DICTIONARIES: readonly (readonly [string, Readonly<Record<string, string>>])[] = [
  ['ko', JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8')) as Readonly<Record<string, string>>],
  ['en', JSON.parse(readFileSync('src/i18n/en.json', 'utf-8')) as Readonly<Record<string, string>>],
];

function expectWords(keys: readonly string[]) {
  for (const [language, dictionary] of DICTIONARIES) {
    for (const key of keys) {
      expect(dictionary[key]?.trim(), `${language} ${key}`).toBeTruthy();
    }
  }
}

function codesOf(file: string): string[] {
  return [...readFileSync(`${CORE}/${file}`, 'utf-8').matchAll(/code\(Group\.\w+,\s*"(\w+)"/g)].map(
    (match) => match[1] ?? '',
  );
}

/**
 * The words the decision details read against the core source (moved from the old factWordsSource.test.ts at I-10,
 * DEC-80; kept out of src: src has no node types): the prompt's entry names the details name each fact by
 * (`ux/runs/factKey.ts`), and every reason code and hypothesis word the evidence tab shows.
 */
describe('decision detail words of the core source', () => {
  it('lists every entry of the core dictionary, numbered entries by their stem, each named in both languages', () => {
    const entries = [
      ...readFileSync(`${CORE}/SecurityDecisionPromptDictionary.java`, 'utf-8').matchAll(
        /entry\(PromptBlock\.\w+,\s*"([^"]+)"/g,
      ),
    ].map((match) => (match[1] ?? '').replace('{i}', ''));
    // 76 entries of the v20 dictionary, the v21 dictionary's TargetScope (v21.4), its eight lines of an agent's request
    // (docs/agent A2, A4, F-5) and ArgumentOrigin (v21.18, CQ-1).
    expect(entries).toHaveLength(86);
    expect([...FACT_LABELS].sort()).toEqual([...entries].sort());
    expectWords([...FACT_LABELS, 'other'].map((label) => `fact.label.${label}`));
  });

  it('names every reason code of both output contracts and every hypothesis and its assessment', () => {
    const codes = codesOf('SecurityDecisionOutputContract.java');
    expect(codes.length).toBeGreaterThan(50);
    expectWords(codes.map((code) => `reasonCode.${code}`));
    // 51 codes: the 49 of the v4 contract as first written, RECORD_COVERS_WORK and VALUE_FROM_UNTRUSTED_OUTPUT.
    const v4 = codesOf('SecurityDecisionOutputContractV4.java');
    expect(v4).toHaveLength(51);
    expectWords(v4.map((code) => `reasonCodeV4.${code}`));
    expectWords(['H1', 'H2', 'H3', 'H4', 'H5'].map((id) => `hypothesis.${id}`));
    expectWords(
      ['MOST_LIKELY', 'POSSIBLE', 'UNLIKELY', 'NO_EVIDENCE'].map(
        (assessment) => `hypothesis.assessment.${assessment}`,
      ),
    );
  });
});
