import { describe, expect, it } from 'vitest';
import type { InspectionCheck, PromptFact, RunFacts, RunQuality } from '../../api/promptQuality';
import en from '../../i18n/en.json';
import ko from '../../i18n/ko.json';
import { GLOSSARY } from '../common/glossaryTerms';
import { factKey, factNoteKey, failuresFirst, ribbonHolds, ribbonLines, sourcesOf } from './factWords';

const DICTIONARIES: readonly (readonly [string, Readonly<Record<string, string>>])[] = [
  ['ko', ko],
  ['en', en],
];

function expectWords(keys: readonly string[]) {
  for (const [language, dictionary] of DICTIONARIES) {
    for (const key of keys) {
      expect(dictionary[key]?.trim(), `${language} ${key}`).toBeTruthy();
    }
  }
}

function line(label: string, value: string, source: PromptFact['source'] = 'COMPUTED'): PromptFact {
  return { line: 1, factId: null, label, value, source, grades: [] };
}

/**
 * U-1, U-8: every word the prompt trust parts show is in both dictionaries (dictionaries.test.ts: same keys). The
 * words of the core's v20 dictionary and reason codes are checked against the core source in factWordsSource.test.ts.
 */
describe('prompt trust words', () => {
  it('holds the eight new glossary terms with their plain words (U-8)', () => {
    const terms = ['factSource', 'fact', 'reasonCode', 'seal', 'delivery', 'reaction', 'invariance', 'injection'];
    expect(GLOSSARY).toEqual(expect.arrayContaining(terms));
    expectWords(terms.flatMap((term) => [`glossary.${term}.term`, `glossary.${term}.plain`]));
    expect(terms.map((term) => (ko as Readonly<Record<string, string>>)[`glossary.${term}.term`])).toEqual([
      '출처',
      '사실',
      '근거 코드',
      '봉인',
      '전달',
      '반응',
      '불변',
      '주입',
    ]);
  });

  it("calls the decision details' raw tab 'original and checks' under its old key", () => {
    expect((ko as Readonly<Record<string, string>>)['detail.tab.original']).toBe('원문·검증');
  });
});

describe('prompt trust reading', () => {
  it('reads a numbered line by its entry and a line the dictionary does not list as other', () => {
    expect(factKey('PastRecord3')).toBe('PastRecord');
    expect(factKey('PastRecordCounts')).toBe('PastRecordCounts');
    expect(factKey('UntrustedText12')).toBe('UntrustedText');
    expect(factKey('UntrustedTextX')).toBe('other');
    expect(factKey('Nonsense')).toBe('other');
  });

  it("reuses W3-10's plain words of a v20 line for the fact on it", () => {
    expect(factNoteKey('DECISION_FACTS', line('PolicySatisfied', 'no — no approval for GB-500'))).toBe(
      'prompt.plain.approvalMissing',
    );
    expect(factNoteKey('REQUEST', line('Roles', 'SC_ADMIN; source SECURITY_CONTEXT'))).toBe('prompt.plain.roles');
    expect(factNoteKey('DECISION_FACTS', line('PolicySatisfied', 'yes — approval APR-1'))).toBeNull();
  });

  it("lists a part's sources once each, in the order its facts state them", () => {
    expect(
      sourcesOf([line('A', '1', 'HOST'), line('B', '2', 'COMPUTED'), line('C', '3', 'HOST'), line('D', '4', null)]),
    ).toEqual(['HOST', 'COMPUTED', null]);
  });

  it("reads whether a ribbon item holds from the server's own counts", () => {
    expect(
      ribbonHolds({ facts: 12, withSource: 12, factAccuracy: { matched: 9, total: 10 }, contradictions: 1, unknown: 3 }),
    ).toEqual({ source: true, accuracy: false, contradictions: false });
    // The seal has no inspection yet: the two items the inspection gives are not decided either way.
    expect(
      ribbonHolds({ facts: 12, withSource: 11, factAccuracy: null, contradictions: null, unknown: 3 }),
    ).toEqual({ source: false, accuracy: null, contradictions: null });
  });

  it('leads each failing item to the first fact behind it', () => {
    const facts: RunFacts = {
      runId: 'run-1',
      stepNo: 1,
      available: true,
      reason: null,
      bundle: null,
      blocks: [
        { block: 'REQUEST', facts: [{ ...line('Time', 'Wed 03:17'), line: 7 }] },
        { block: 'UNKNOWN', facts: [{ ...line('Unknown', 'PeerCohort', null), line: 30 }] },
      ],
    };
    const check = (code: string, lines: readonly number[]): InspectionCheck => ({
      code,
      matched: 1,
      mismatched: lines.length,
      unverifiable: 0,
      mismatches: lines.map((number) => ({
        block: null,
        entry: null,
        factId: null,
        line: number,
        expected: null,
        actual: null,
        reason: null,
      })),
    });
    const quality: RunQuality = {
      available: true,
      reason: null,
      bundle: null,
      seal: null,
      reasonCodes: [],
      ribbon: null,
      inspection: {
        verdict: 'FAIL',
        inspectorVersion: null,
        inspectedAt: null,
        checks: [check('SEAL_INTEGRITY', []), check('SAME_FACT', [12]), check('DECISION_FACT_MATCH', [9, 10])],
      },
    };
    expect(ribbonLines(quality, facts)).toEqual({ source: 30, accuracy: 9, contradictions: 12 });
    expect(ribbonLines(null, null)).toEqual({ source: null, accuracy: null, contradictions: null });
    expect(failuresFirst(quality.inspection?.checks ?? []).map((entry) => entry.code)).toEqual([
      'SAME_FACT',
      'DECISION_FACT_MATCH',
      'SEAL_INTEGRITY',
    ]);
  });
});
