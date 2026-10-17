import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * U6-7 (screen design reinforcement 3.5, line 166): on phones the prompt-quality tab's four big numbers
 * slide sideways a card at a time inside their own region, and the other numbers stay a list read top to
 * bottom. jsdom lays nothing out, so the stylesheet's rules are read; the region itself is asserted in
 * src/pages/benchmark/BenchPromptPage.test.tsx.
 */
const css = readFileSync('src/pages/benchmark/BenchPrompt.module.css', 'utf-8').replace(/\r\n/g, '\n');

/** The declarations of a class rule inside a block of the stylesheet. */
function rule(block: string, name: string): string {
  const found = new RegExp(`(?:^|\\n)\\s*\\.${name} \\{([^}]*)\\}`).exec(block)?.[1];
  if (found === undefined) {
    throw new Error(`missing .${name}`);
  }
  return found;
}

describe('prompt-quality tab on phones', () => {
  it('slides the four big numbers sideways a card at a time, the rest top to bottom', () => {
    const phone = /@media \(width <= 40rem\) \{([\s\S]*?)\n\}/.exec(css)?.[1] ?? '';
    expect(rule(phone, 'cardsScroll')).toMatch(/overflow-x: auto;/);
    expect(rule(phone, 'cardsScroll')).toMatch(/scroll-snap-type: x mandatory;/);
    expect(rule(phone, 'cards')).toMatch(/grid-auto-flow: column;/);
    expect(rule(phone, 'card')).toMatch(/scroll-snap-align: start;/);
    // The other numbers are one list read top to bottom at every width.
    expect(rule(css, 'more')).toMatch(/flex-direction: column;/);
  });
});
