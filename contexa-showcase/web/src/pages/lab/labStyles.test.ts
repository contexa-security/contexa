import { describe, expect, it } from 'vitest';

/** Node's file reader, typed here: the app's type set has no Node types, and vitest runs these tests in Node. */
type ReadFile = (path: string, encoding: 'utf-8') => string;
const FS = 'node:fs';
const { readFileSync } = (await import(/* @vite-ignore */ FS)) as { readonly readFileSync: ReadFile };

/**
 * Layout rules of the lab's screens found in the review before the guide videos (2026-10-21, L-03, L-20, L-23, L-24).
 * jsdom lays nothing out, so the stylesheet's rules are read; what the screens render is asserted in
 * LabScreens.test.tsx.
 */
const lab = readFileSync('src/pages/lab/LabScreens.module.css', 'utf-8').replace(/\r\n/g, '\n');

/** The declarations of a rule of the stylesheet, by its selector as written (inside a media query too). */
function rule(selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const found = new RegExp(`(?:^|\\n) *${escaped} \\{([^}]*)\\}`).exec(lab)?.[1];
  if (found === undefined) {
    throw new Error(`missing ${selector}`);
  }
  return found;
}

describe('the body width of the lab (L-03)', () => {
  it('lets the boxes of a screen (card, field, inputs) end where the action bar and its line end', () => {
    for (const selector of ['.card', '.field', '.controls']) {
      expect(rule(selector)).toContain('max-width: var(--frame-wide);');
    }
    // Plain text keeps the reading width (화면재편-기획안 5절, 10절).
    expect(rule('.line')).toContain('max-width: var(--frame-measure);');
  });

  it('sets the three inputs of the rule tightening in one row on wide screens', () => {
    expect(rule('.controls[data-three]')).toContain('grid-template-columns: repeat(3, minmax(0, 1fr));');
  });
});

describe('a main button that waits (L-20, L-23)', () => {
  it('draws a disabled main button solid and muted at every width, as the phone bar does', () => {
    for (const selector of ['.send:disabled', '.nextOff']) {
      const declarations = rule(selector);
      expect(declarations).toContain('background-color: var(--color-surface-raised);');
      expect(declarations).toContain('color: var(--color-text-muted);');
      expect(declarations).not.toContain('opacity: 0.45');
    }
  });
});

describe('the rule tightening (L-24)', () => {
  it('keeps the count columns’ headings on one line', () => {
    expect(rule('.table[data-numbers] thead th')).toContain('white-space: nowrap;');
  });

  it('keeps a date and time whole', () => {
    expect(rule('.whole')).toContain('white-space: nowrap;');
  });
});
