import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { dictionaryPart, firstKeys, namedIn } from './dictionarySplit';

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

  it("puts the first screens' words in the first part and the other spaces' words in the rest", () => {
    const first = firstKeys(web, Object.keys(dictionary('ko')));
    for (const key of [
      'ux.home.title.line1',
      'ux.menu.home',
      'ux.review.run',
      'ux.live.title',
      'ux.result.exports.title',
      'ux.compare.title',
      'ux.recovery.check.title',
    ]) {
      expect(first.has(key), key).toBe(true);
    }
    // The old screens have no address of their own any more (UX-R1 DEC-14): their words wait in the rest.
    for (const key of ['bench.r7.summary.title', 'main.1-1.title']) {
      expect(first.has(key), key).toBe(false);
    }
  });

  it('reads a key named inside a template literal, as a first screen writes a value after its words', () => {
    const named = namedIn("{wait ? ` ${t('ux.live.queuedWait', { seconds })}` : ''} {`${title} ${t('ux.flow.run')}`}");
    expect(named.whole.has('ux.live.queuedWait')).toBe(true);
    expect(named.whole.has('ux.flow.run')).toBe(true);
    expect(namedIn('t(`ux.recovery.cause.${cause}`)').heads.has('ux.recovery.cause.')).toBe(true);
  });

  it('keeps the first part under half of the dictionary, so the first screen reads less', () => {
    const keys = Object.keys(dictionary('ko'));
    expect(firstKeys(web, keys).size).toBeLessThan(keys.length / 2);
  });
});
