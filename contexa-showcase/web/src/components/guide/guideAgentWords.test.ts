import { describe, expect, it } from 'vitest';
import en from '../../i18n/en.json';
import ko from '../../i18n/ko.json';
import scripts from './guides.json';

const BOOKS = { ko: ko as Readonly<Record<string, string>>, en: en as Readonly<Record<string, string>> };

/**
 * docs/agent A7-4 (가이드영상-계획.md 6절 G-3): the business agent guide's lines name the screens' own words: the
 * delegation record's rows, the send button, the five approaches and the delegating person's two answers.
 */
describe('the business agent guide speaks the screens words', () => {
  it('has every scene line in both languages', () => {
    for (const book of Object.values(BOOKS)) {
      for (const key of [scripts.agent.title, ...scripts.agent.scenes]) {
        expect(book[key], key).toBeTruthy();
      }
    }
  });

  it.each(Object.entries(BOOKS))('uses the screen words in %s', (_language, book) => {
    const words = (key: string) => book[key] ?? `missing ${key}`;
    expect(words('guide.agent.send')).toContain(words('main.6-1.send'));
    expect(words('guide.agent.reason')).toContain(
      words('main.6-3.difference').toLowerCase().replace(/^the /, ''),
    );
    for (const control of ['A', 'B', 'C1', 'C2', 'D']) {
      expect(words('guide.agent.rows').toLowerCase()).toContain(
        words(`control.${control}.name`).toLowerCase(),
      );
    }
  });

  it('names the scope and the period as the delegation record does (ko)', () => {
    expect(BOOKS.ko['guide.agent.work']).toContain(BOOKS.ko['main.agent.scope']);
    expect(BOOKS.ko['guide.agent.work']).toContain(BOOKS.ko['main.agent.period']);
  });
});
