import { describe, expect, it } from 'vitest';
import { PRIVACY } from './policies';

describe('privacy notice', () => {
  it('has the same structure in Korean and English', () => {
    expect(PRIVACY.ko.sections.length).toBe(PRIVACY.en.sections.length);
    PRIVACY.ko.sections.forEach((section, index) => {
      const other = PRIVACY.en.sections[index];
      expect(section.paragraphs?.length, String(index)).toBe(other?.paragraphs?.length);
      expect(
        section.table?.map((row) => row.length),
        String(index),
      ).toEqual(other?.table?.map((row) => row.length));
    });
  });

  it('keeps every stored item and period of the data list, in the plain terms (R7, 화면재편-기획안 11절)', () => {
    const korean = JSON.stringify(PRIVACY.ko);
    // The facts: what is kept and for how long, unchanged by the change of words.
    for (const fact of [
      '마지막 방문 뒤 30일',
      '방문자 식별자와 같음',
      '30일. 방문자와 연결되는 값은 없습니다',
      '7일',
      '마지막 공유 뒤 90일',
      '매일 03:30(세계 표준시)',
      'Cloudflare Turnstile',
    ]) {
      expect(korean, fact).toContain(fact);
    }
    for (const old of [
      '허용',
      '판정',
      '정답',
      '맞음',
      '틀림',
      '엔진',
      '원문',
      '실행',
      '측정',
      '근거',
      '각 막',
      '막별',
      '도착한 막',
    ]) {
      expect(korean, old).not.toContain(old);
    }
    const english = JSON.stringify(PRIVACY.en);
    for (const fact of [
      '30 days after the last visit',
      '7 days',
      '90 days after the last share',
      '03:30 UTC',
    ]) {
      expect(english, fact).toContain(fact);
    }
    for (const old of [/\bact\b/, /\bacts\b/, /\bengine\b/, /\ballow\b/, /\bruns?\b/]) {
      expect(english).not.toMatch(old);
    }
  });

  it('names every cookie the portal sets, and nothing internal', () => {
    for (const language of ['ko', 'en'] as const) {
      const cookies = PRIVACY[language].sections
        .filter((section) => section.table?.[0]?.[0] === (language === 'ko' ? '이름' : 'Name'))
        .flatMap((section) => (section.table ?? []).slice(1).map((row) => row[0]));
      expect(cookies).toEqual(['SC_VISITOR', 'XSRF-TOKEN']);
    }
    const text = JSON.stringify(PRIVACY);
    for (const internal of ['Q-', 'P5-', 'TODO', '승인대기', 'showcase_portal', '/ops/', 'SC_CONSENT']) {
      expect(text).not.toContain(internal);
    }
  });
});
