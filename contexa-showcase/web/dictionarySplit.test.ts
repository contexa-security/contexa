import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { dictionaryPart, firstKeys } from './dictionarySplit';

// The tests run from the web folder, as the other root tests do.
const web = process.cwd();

function dictionary(language: string): Record<string, string> {
  return JSON.parse(readFileSync(join(web, 'src/i18n', `${language}.json`), 'utf8')) as Record<
    string,
    string
  >;
}

describe('the dictionary in two parts (FC-4)', () => {
  it('splits each language into a first part and a rest that together hold every key once, with its words', () => {
    for (const language of ['ko', 'en']) {
      const whole = dictionary(language);
      const first = dictionaryPart(web, language, 'first');
      const rest = dictionaryPart(web, language, 'rest');
      expect(Object.keys(first).filter((key) => key in rest)).toEqual([]);
      expect({ ...first, ...rest }).toEqual(whole);
    }
  });

  it('splits both languages the same way', () => {
    expect(Object.keys(dictionaryPart(web, 'en', 'first')).sort()).toEqual(
      Object.keys(dictionaryPart(web, 'ko', 'first')).sort(),
    );
  });

  it("puts the main flow's words in the first part and the other spaces' words in the rest", () => {
    const first = firstKeys(web, Object.keys(dictionary('ko')));
    for (const key of [
      'main.1-1.title',
      'main.2-1.title',
      'main.console.storing',
      'cover.start',
      'frame.menu',
    ]) {
      expect(first.has(key), key).toBe(true);
    }
    for (const key of ['bench.r7.summary.title']) {
      expect(first.has(key), key).toBe(false);
    }
  });

  it('keeps the first part under half of the dictionary, so the first screen reads less', () => {
    const keys = Object.keys(dictionary('ko'));
    expect(firstKeys(web, keys).size).toBeLessThan(keys.length / 2);
  });
});
