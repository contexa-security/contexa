import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * U6-7, redone for the redesigned table view (화면재편-구현계획 RO-3): on phones the seven values of the text sent to
 * the AI stay one table that slides sideways inside its own region, so no column is squashed and the page never
 * scrolls sideways. jsdom lays nothing out, so the stylesheets' rules are read; the region itself is asserted in
 * src/pages/benchmark/BenchPromptPage.test.tsx.
 */
const read = (path: string) => readFileSync(path, 'utf-8').replace(/\r\n/g, '\n');
const bench = read('src/pages/benchmark/Bench.module.css');
const prompt = read('src/pages/benchmark/BenchPrompt.module.css');

/** The declarations of a class rule of a stylesheet. */
function rule(css: string, name: string): string {
  const found = new RegExp(`(?:^|\\n)\\.${name} \\{([^}]*)\\}`).exec(css)?.[1];
  if (found === undefined) {
    throw new Error(`missing .${name}`);
  }
  return found;
}

describe('the text sent to the AI on phones', () => {
  it('slides the one table sideways inside its region instead of squashing its columns', () => {
    expect(rule(bench, 'tableScroll')).toMatch(/overflow-x: auto;/);
    expect(rule(prompt, 'table')).toMatch(/min-width: \d+(\.\d+)?rem;/);
    // The value of a row never breaks.
    expect(rule(prompt, 'value')).toMatch(/white-space: nowrap;/);
  });
});
