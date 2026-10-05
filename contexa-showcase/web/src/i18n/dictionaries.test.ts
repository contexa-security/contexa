import { describe, expect, it } from 'vitest';
import en from './en.json';
import ko from './ko.json';

/** Internal planning terms that must never reach the visitor screens (copy glossary, deck page 22). */
const INTERNAL_TERMS_KO = ['조정에 쓰지 않은', '쌍둥이 요청', '업무 세계의 사실', '제어 전환', '보류 군', '집행 전 노출량'];
const INTERNAL_TERMS_EN = ['held-out group', 'twin request', 'business world fact', 'control handover'];

describe('visitor dictionaries', () => {
  it('have exactly the same keys in Korean and English', () => {
    expect(Object.keys(ko).sort()).toEqual(Object.keys(en).sort());
  });

  it('have no empty values', () => {
    for (const [key, value] of [...Object.entries(ko), ...Object.entries(en)]) {
      expect(value.trim(), key).not.toBe('');
    }
  });

  it('never contain internal planning terms', () => {
    for (const value of Object.values(ko)) {
      for (const term of INTERNAL_TERMS_KO) {
        expect(value).not.toContain(term);
      }
    }
    for (const value of Object.values(en)) {
      for (const term of INTERNAL_TERMS_EN) {
        expect(value.toLowerCase()).not.toContain(term);
      }
    }
  });
});
