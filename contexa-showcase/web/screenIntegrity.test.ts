import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DEFAULT_ROUTE } from './src/journey/journey';

/**
 * Integrity of the visitor screens (H-11, C-2, C-10, C-19): the screens compute nothing and hold no measured number,
 * the teaser copy is the 0-3 table of the screen design, and every case key the code names exists.
 */
const DESIGN = '../../docs/showcase/화면설계서-v2.md';
const PLAN = '../../docs/showcase/화면설계서-v2-구현계획.md';
const SCENARIOS = '../showcase-portal/src/main/resources/scenarios';

const dictionary = (language: string): Record<string, string> =>
  JSON.parse(readFileSync(`src/i18n/${language}.json`, 'utf-8')) as Record<string, string>;

/** The visitor screens' code: every source file but tests, test helpers and the development-only design pages. */
function sources(dir: string): string[] {
  const files: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name !== 'test' && name !== 'design') {
        files.push(...sources(path));
      }
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name)) {
      files.push(path);
    }
  }
  return files;
}

/** The code without its comments, so a comment that quotes a measured value is not mistaken for a constant. */
function code(path: string): string {
  return readFileSync(path, 'utf-8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** Measured values of the screen design's examples (plan 8절): the screens must take them from the server. */
const MEASURED = [/\b4,?831\b/, /\b7,?964\b/, /\b22,?637\b/, /\b342\b/, /\b369\b/];

describe('visitor screen integrity', () => {
  it('holds no measured number in the code', () => {
    const files = sources('src');
    expect(files.length).toBeGreaterThan(50);
    for (const path of files) {
      const text = code(path);
      for (const pattern of MEASURED) {
        expect(pattern.test(text), `${path} ${pattern}`).toBe(false);
      }
    }
  });

  it('writes measured numbers of teasers, act-end sentences and just-seen lines only as placeholders', () => {
    for (const language of ['ko', 'en']) {
      for (const [key, value] of Object.entries(dictionary(language))) {
        if (/^(teaser|actEnd|justSaw)\./.test(key)) {
          expect(value.replace('/6', ''), `${language} ${key}`).not.toMatch(/\d/);
        }
      }
    }
  });

  it('uses the 0-3 table of the screen design as the teaser copy', () => {
    const design = readFileSync(DESIGN, 'utf-8').replace(/\r\n/g, '\n');
    const start = design.indexOf('### 궁금증 사슬: 예고 카드');
    const rows = design
      .slice(start, design.indexOf('### 막 끝 카드', start))
      .split('\n')
      .filter((line) => line.startsWith('|') && !line.startsWith('|---') && !line.includes('예고 질문'))
      .map((line) => line.split('|').map((cell) => cell.trim()));
    const keys = DEFAULT_ROUTE.filter((screen) => screen.teaser).map((screen) => screen.teaser as string);
    expect(rows).toHaveLength(15);
    expect(keys).toHaveLength(15);
    const shape = (text: string) => text.replace(/\{\{\w+\}\}/g, '#').replace(/\d[\d,.]*/g, '#');
    const ko = dictionary('ko');
    rows.forEach((row, index) => {
      const key = keys[index];
      expect(shape(ko[`teaser.${key}.question`] ?? ''), key).toBe(shape(row[2] ?? ''));
      expect(shape(ko[`teaser.${key}.teaser`] ?? ''), key).toBe(shape(row[3] ?? ''));
    });
  });

  it('uses the copy source table (plan 7.0) for the eight just-seen lines and the one seen-again line', () => {
    const plan = readFileSync(PLAN, 'utf-8').replace(/\r\n/g, '\n');
    const start = plan.indexOf('### 7.0 문구 원천표');
    const rows = new Map(
      plan
        .slice(start, plan.indexOf('### 7.1', start))
        .split('\n')
        .filter((line) => line.startsWith('| '))
        .map((line) => line.split('|').map((cell) => cell.trim()))
        .map((cells) => [cells[1] ?? '', cells[4] ?? ''] as const),
    );
    const screens: Readonly<Record<string, string>> = {
      'E1-④ 실행': 'e1Run',
      'E1-② 비교': 'e1Compare',
      'E1-⑥ 근거': 'e1Reason',
      'E1-⑦ 후속': 'e1After',
      'E2-⑤ 결과': 'e2Result',
      'E2-⑦ 본인 확인': 'e2Check',
      T4: 'syncWhen',
      E3: 'e3Stack',
      '판정 뒤 학습': 'learnAfter',
    };
    const shape = (text: string) =>
      text
        .replace(/^(다시 보는 차이 )?[①-⑥] /, '')
        .replace(/\{\{\w+\}\}/g, '#')
        .replace(/\{[\d.,]+\}/g, '#');
    const ko = dictionary('ko');
    for (const [screen, key] of Object.entries(screens)) {
      expect(rows.get(screen), screen).toBeTruthy();
      expect(shape(ko[`justSaw.${key}`] ?? ''), screen).toBe(shape(rows.get(screen) ?? ''));
    }
  });

  it('names only cases that exist', () => {
    const cases = new Set(readdirSync(SCENARIOS).map((name) => name.replace(/\.json$/, '')));
    expect(cases.size).toBeGreaterThan(20);
    for (const path of sources('src')) {
      for (const match of code(path).matchAll(/['"]((?:A\d+[A-Z]*)|(?:S\d{2}[A-Z]*)|(?:K\d)|(?:R\d))['"]/g)) {
        expect(cases.has(match[1] ?? ''), `${path} names ${match[1]}`).toBe(true);
      }
    }
  });
});
