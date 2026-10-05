import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The preloaded demo font (scripts/font-subset.py) must cover every character the visitor screens show; a new word
 * in the dictionaries or the visitor content fails here until the font is rebuilt.
 */
const covered = new Set(Array.from(readFileSync('public/fonts/pretendard-demo.chars.txt', 'utf-8').trim()));

function texts(): string {
  const dictionaries = ['src/i18n/ko.json', 'src/i18n/en.json'].map((file) =>
    Object.values(JSON.parse(readFileSync(file, 'utf-8')) as Record<string, string>).join(''),
  );
  const content = readdirSync('src/content')
    .filter((file) => file.endsWith('.ts') && !file.includes('.test.'))
    .map((file) => readFileSync(join('src/content', file), 'utf-8'));
  return [...dictionaries, ...content].join('');
}

describe('demo font coverage', () => {
  it('covers every non-ASCII character of the visitor texts', () => {
    const missing = [...new Set(Array.from(texts()))].filter(
      (character) =>
        (character.codePointAt(0) ?? 0) >= 0x80 && !/\s/.test(character) && !covered.has(character),
    );
    expect(missing).toEqual([]);
  });
});
