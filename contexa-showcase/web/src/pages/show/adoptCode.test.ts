import { describe, expect, it } from 'vitest';
import { ADOPT_CODE } from './adoptCode';

/** Scene 5 highlights only the line that turns Contexa on or protects the method (docs/showcase/화면설계서.md). */
describe('the code of scene 5', () => {
  it('highlights the Contexa annotation and nothing else', () => {
    const highlighted = ADOPT_CODE.map((excerpt) => excerpt.lines[excerpt.highlight]?.trim());
    expect(highlighted).toEqual(['@EnableAISecurity(mode = SecurityMode.FULL)', '@Protectable']);
  });
});
