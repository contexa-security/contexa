import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  CHUNKS,
  FACT_LABELS,
  FACT_SOURCES,
  FOLDS,
  INSPECTION_CHECKS,
  INSPECTION_VERDICTS,
} from './src/components/facts/factWords';

/** The core's v20 dictionary and output contract, read as the source of the entry names and the reason codes. */
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

/**
 * U-1, U-8 against the core source (kept out of src: src has no node types, and the build's tsc -b checks src):
 * every entry of the core v20 dictionary and every reason code has its words in both dictionaries.
 */
describe('prompt trust words of the core source', () => {
  it('names and explains every entry of the core v20 dictionary, numbered entries by their stem', () => {
    const entries = [...readFileSync(`${CORE}/SecurityDecisionPromptDictionary.java`, 'utf-8').matchAll(/entry\(PromptBlock\.\w+,\s*"([^"]+)"/g)].map((match) =>
      (match[1] ?? '').replace('{i}', ''),
    );
    expect(entries).toHaveLength(76);
    expect([...FACT_LABELS].sort()).toEqual([...entries].sort());
    expectWords([...FACT_LABELS, 'other'].flatMap((label) => [`fact.label.${label}`, `fact.meaning.${label}`]));
  });

  it('names every reason code, the five sources, the checks, the verdicts and every part and fold', () => {
    const codes = [...readFileSync(`${CORE}/SecurityDecisionOutputContract.java`, 'utf-8').matchAll(/code\(Group\.\w+,\s*"(\w+)"/g)].map((match) => match[1] ?? '');
    expect(codes.length).toBeGreaterThan(50);
    expectWords(codes.map((code) => `reasonCode.${code}`));
    expectWords([...FACT_SOURCES, 'NONE'].map((source) => `fact.source.${source}`));
    expectWords(INSPECTION_CHECKS.map((code) => `quality.check.${code}`));
    expectWords(INSPECTION_VERDICTS.map((verdict) => `quality.verdict.${verdict}`));
    expectWords([...CHUNKS, ...FOLDS].flatMap((block) => [`prompt.block.${block}`, `prompt.blockWhat.${block}`]));
    expectWords([
      'quality.ribbon.title',
      'quality.ribbon.source',
      'quality.ribbon.accuracy',
      'quality.ribbon.contradictions',
      'quality.ribbon.unknown',
      'reasonChain.noLink',
      'labDelta.passed',
      'labDelta.failed',
      'benchBar.view.prompt',
      'promptQuality.notMeasured',
      'detail.verify.sealCheck',
      'detail.verify.sealSame',
      'prompt.compare.title',
      'prompt.compare.lead',
      'quality.ribbon.accuracyPending',
      'quality.ribbon.contradictionsPending',
      'benchmark.suite.NORMAL_COMBINATION',
    ]);
    expectWords(['NO_STEP', 'NOT_SEALED', 'NO_ENGINE', 'other'].map((reason) => `factsReason.${reason}`));
    expectWords(
      ['DESIGNED', 'SEVERAL_CONDITIONS', 'NOT_COMPLETED', 'NO_BASE', 'NO_ENGINE', 'other'].map(
        (reason) => `labDelta.reason.${reason}`,
      ),
    );
    expectWords(['NO_VARIANT_STEP', 'NOT_SEALED'].map((reason) => `labDelta.notCompared.${reason}`));
  });
});
