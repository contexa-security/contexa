import { describe, expect, it } from 'vitest';
import en from '../../i18n/en.json';
import ko from '../../i18n/ko.json';
import { G_RULES_PLAIN } from '../../pages/intro/rulesLines';
import { ruleKey } from './detailWords';

const KO: Readonly<Record<string, string>> = ko;
const EN: Readonly<Record<string, string>> = en;

// Review before the guide videos (2026-10-21): the v21 lines showed their keys in the rules tab.
describe('the rules tab', () => {
  it('names every rule line of every bundle in words, in Korean and English', () => {
    for (const plain of G_RULES_PLAIN) {
      const koKey = ruleKey(plain.key, (key) => key in KO);
      const enKey = ruleKey(plain.key, (key) => key in EN);
      expect(KO[koKey], koKey).toBeTruthy();
      expect(EN[enKey], enKey).toBeTruthy();
    }
  });

  it("keeps the tab's own words where it has them", () => {
    expect(ruleKey('gRules.plain.lowRisk', () => true)).toBe('detail.r7.rule.lowRisk');
    expect(ruleKey('gRules.plain.v21Mission', (key) => key !== 'detail.r7.rule.v21Mission')).toBe(
      'gRules.plain.v21Mission',
    );
  });
});
