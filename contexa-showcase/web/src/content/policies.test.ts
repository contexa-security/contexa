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
