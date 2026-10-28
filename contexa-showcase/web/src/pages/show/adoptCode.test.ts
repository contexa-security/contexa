import { describe, expect, it } from 'vitest';
import { ADOPT_CODE } from './adoptCode';

/** Scene 5 highlights only the lines that turn Contexa on or protect the method (docs/showcase/화면설계서.md). */
describe('the code of scene 5', () => {
  it('highlights the Contexa annotation and nothing else', () => {
    const highlighted = ADOPT_CODE.map((excerpt) => excerpt.highlight.map((index) => excerpt.lines[index]?.trim()));
    expect(highlighted[0]).toEqual(['@EnableAISecurity(mode = SecurityMode.FULL)']);
    // The protected method's annotation as the business code writes it, with whatever attributes it names; it may
    // continue on the next line (the importance of the resource is declared there), and then both lines are lit.
    expect(highlighted[1]?.[0]).toMatch(/^@Protectable(\(|$)/);
    expect(highlighted[1]?.join(' ')).toContain('importance = ResourceImportance.SENSITIVE)');
    expect(highlighted).toHaveLength(2);
  });

  it('lights only lines that exist in the excerpt', () => {
    for (const excerpt of ADOPT_CODE) {
      expect(excerpt.highlight.length).toBeGreaterThan(0);
      for (const index of excerpt.highlight) {
        expect(excerpt.lines[index], `${excerpt.path} line ${index}`).toBeDefined();
      }
    }
  });
});
