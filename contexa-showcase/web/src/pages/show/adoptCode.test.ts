import { describe, expect, it } from 'vitest';
import { ADOPT_CODE } from './adoptCode';

/** Scene 5 highlights only the line that turns Contexa on or protects the method (docs/showcase/화면설계서.md). */
describe('the code of scene 5', () => {
  it('highlights the Contexa annotation and nothing else', () => {
    const highlighted = ADOPT_CODE.map((excerpt) => excerpt.lines[excerpt.highlight]?.trim());
    expect(highlighted[0]).toBe('@EnableAISecurity(mode = SecurityMode.FULL)');
    // The protected method's annotation as the business code writes it, with whatever attributes it names.
    expect(highlighted[1]).toMatch(/^@Protectable(\(|$)/);
    expect(highlighted).toHaveLength(2);
  });
});
