import { describe, expect, it } from 'vitest';

/** Node's file reader, typed here: the app's type set has no Node types, and vitest runs these tests in Node. */
type ReadFile = (path: string, encoding: 'utf-8') => string;
const FS = 'node:fs';
const { readFileSync } = (await import(/* @vite-ignore */ FS)) as { readonly readFileSync: ReadFile };

/**
 * Layout rules of the decision details found in the review before the guide videos (2026-10-21, L-03, L-27, L-43).
 * jsdom lays nothing out, so the stylesheet's rules are read; what the tabs render is asserted in
 * DecisionDetail.test.tsx.
 */
const detail = readFileSync('src/components/detail/DecisionDetail.module.css', 'utf-8').replace(/\r\n/g, '\n');

/** The declarations of a rule of the stylesheet, by its selector as written (inside a media query too). */
function rule(selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const found = new RegExp(`(?:^|\\n) *${escaped} \\{([^}]*)\\}`).exec(detail)?.[1];
  if (found === undefined) {
    throw new Error(`missing ${selector}`);
  }
  return found;
}

describe('the window over the screen (L-27)', () => {
  it('darkens and blurs the screen behind the details more than other windows do', () => {
    const backdrop = rule(':global(dialog):has(.detail)::backdrop');
    expect(backdrop).toMatch(/background-color: color-mix\(in srgb, var\(--color-bg\) 8\d%, transparent\);/);
    expect(backdrop).toContain('backdrop-filter: blur(');
  });

  it('keeps the seven tabs on one row at 1440 in both languages', () => {
    expect(rule('.tab')).toContain('padding: 0 var(--space-3);');
  });
});

describe('the width inside a tab (L-03, L-27)', () => {
  it('lets the one chooser of a tab end where the tables end', () => {
    expect(rule('.chooser')).not.toContain('max-inline-size');
  });

  it("lets the received tab's comparison take the tab's width", () => {
    expect(rule('.fill > div')).toContain('max-width: none;');
  });
});

describe('the words that belong together (L-27, L-43)', () => {
  it('keeps a code like HX-310 whole', () => {
    expect(rule('.whole')).toContain('white-space: nowrap;');
  });

  it("keeps each identity check outcome's name with its count on wide screens (phones wrap inside it)", () => {
    const wide = /@media \(width > 40rem\) \{\n {2}\.outcome \{([^}]*)\}/.exec(detail)?.[1] ?? '';
    expect(wide).toContain('white-space: nowrap;');
  });

  it("draws the AI's own text on a ground of its own, so its inner margin reads as a box, not an indent", () => {
    expect(rule('.pre')).toContain('background-color: var(--color-surface-raised);');
  });
});
