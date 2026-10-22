import { describe, expect, it } from 'vitest';

/** Node's file reader, typed here: the app's type set has no Node types, and vitest runs these tests in Node. */
type ReadFile = (path: string, encoding: 'utf-8') => string;
const FS = 'node:fs';
const { readFileSync } = (await import(/* @vite-ignore */ FS)) as { readonly readFileSync: ReadFile };

/**
 * The layout items of the benchmark views from the pre-video review (docs/showcase/영상전-검토.md 10절, L-03 and
 * L-39 to L-41). jsdom lays nothing out, so the stylesheets' rules are read, as benchPromptPhone.test.ts does; what the
 * views render is asserted in their own tests.
 */
const read = (path: string) => readFileSync(path, 'utf-8').replace(/\r\n/g, '\n');
const bench = read('src/pages/benchmark/Bench.module.css');
const charts = read('src/pages/benchmark/charts/Charts.module.css');

/** The declarations of every rule of a stylesheet whose selector list names the selector, outside media queries too. */
function rule(css: string, selector: string): string {
  const found = Array.from(css.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}]+)\{([^{}]*)\}/g))
    .filter((match) =>
      (match[1] ?? '')
        .split(',')
        .map((part) => part.trim())
        .includes(selector),
    )
    .map((match) => match[2] ?? '');
  if (found.length === 0) {
    throw new Error(`missing ${selector}`);
  }
  return found.join('\n');
}

describe('the benchmark views at 1440 px', () => {
  it('lines up the three answer cards of the approaches row by row (L-39)', () => {
    // Each card takes three rows of the list's grid, so the questions, the answers and the values line up across the
    // cards whatever wraps, and no card's answer sits lower than the others'.
    expect(rule(bench, '.question')).toMatch(/grid-row: span 3;/);
    expect(rule(bench, '.question')).toMatch(/grid-template-rows: subgrid;/);
  });

  it("gives the situations' names the room left by the five approaches, underlined below the letters (L-40)", () => {
    // The name column takes what the five approach columns leave (each held to the width of its name), so a name is
    // one line, not two to four.
    expect(rule(charts, '.mapRow')).toMatch(
      /grid-template-columns: minmax\(\d+rem, 1fr\) repeat\(5, minmax\(\d+(\.\d+)?rem, \d+(\.\d+)?rem\)\);/,
    );
    // The dotted underline sits under the letters, never across the final consonants.
    expect(rule(charts, '.caseName')).toMatch(/text-underline-offset: [^;]+;/);
  });

  it('draws the filter as a clear control, not a small faint checkbox (L-40)', () => {
    expect(rule(charts, '.filter')).toMatch(/border: 1px solid var\(--color-border-strong\);/);
    expect(rule(charts, '.filter')).toMatch(/color: var\(--color-text\);/);
    const box = rule(charts, '.filter input');
    expect(box).toMatch(/accent-color: var\(--color-accent\);/);
    expect(box).toMatch(/width: 1\.25rem;/);
    expect(box).toMatch(/height: 1\.25rem;/);
  });

  it('writes the labels under the numbers and the empty line of the limits in the body colour (L-41)', () => {
    expect(rule(bench, '.figures dt')).toMatch(/color: var\(--color-text-body\);/);
    expect(rule(charts, '.noneLine')).toMatch(/color: var\(--color-text-body\);/);
  });

  it('keeps text at the reading width and boxes, figures and choosers at the wide width of the frame (L-03)', () => {
    // 화면재편-기획안 5절, 10절: the bottom rule and buttons use the frame's wide width, so a box, a figure or a chooser
    // ends where they end; plain text keeps the reading width.
    for (const box of ['.callouts', '.callout', '.choice']) {
      expect(rule(bench, box)).toMatch(/max-width: var\(--frame-wide\);/);
    }
    // The summary's five criteria are rows with their values at the right end, a table: wide too.
    for (const box of ['.figure', '.pairs', '.proofLines']) {
      expect(rule(charts, box)).toMatch(/max-width: var\(--frame-wide\);/);
    }
    for (const text of ['.line', '.proofLines', '.explain']) {
      expect(rule(bench, text)).toMatch(/max-width: var\(--frame-measure\);/);
    }
    // The original words in the trust view's table: the demo's monospace at the regular weight in both languages,
    // not the browser's own monospace (bold in English, thin in Korean).
    const code = rule(bench, '.table code');
    expect(code).toMatch(/font-family: var\(--font-mono\);/);
    expect(code).toMatch(/font-weight: var\(--weight-regular\);/);
  });
});
