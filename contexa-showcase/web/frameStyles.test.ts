import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * Layout rules of the shared frame and the timing part found in the review before the guide videos (2026-10-21, L).
 * jsdom lays nothing out, so the stylesheets' rules are read; what the screens render is asserted in their own tests.
 */
const read = (path: string) => readFileSync(path, 'utf-8').replace(/\r\n/g, '\n');
const tokens = read('src/styles/tokens.css');
const header = read('src/components/AppHeader.module.css');
const timing = read('src/pages/try/timing/Timing.module.css');

/** The declarations of a rule of a stylesheet, by its selector as written. */
function rule(css: string, selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const found = new RegExp(`(?:^|\\n)${escaped} \\{([^}]*)\\}`).exec(css)?.[1];
  if (found === undefined) {
    throw new Error(`missing ${selector}`);
  }
  return found;
}

describe('numbers in the top bar (L-01)', () => {
  it('writes them in the body font with digits of one width, never the mono font whose slashed zero reads as Ø', () => {
    expect(tokens).toMatch(/\n {2}--font-figures: var\(--font-sans\);/);
    const numbers = rule(header, '.stats b');
    expect(numbers).toContain('font-family: var(--font-figures);');
    expect(numbers).toContain('font-variant-numeric: tabular-nums;');
    expect(numbers).not.toContain('--font-mono');
  });
});

describe('the two questions of 4-3 (L-12)', () => {
  it("keeps the questions a block apart, wider than the lines inside one, so a 'no' never sits on the next question", () => {
    expect(rule(timing, '.questions')).toContain('gap: var(--frame-block-gap);');
    expect(rule(timing, '.question')).toContain('gap: var(--frame-inner-gap);');
  });
});
