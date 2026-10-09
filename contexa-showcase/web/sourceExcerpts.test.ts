import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ADOPT_CODE } from './src/pages/show/adoptCode';

/**
 * The code a visitor screen shows as this demo's own (docs/showcase/화면설계서.md scene 5) must be the source line for
 * line; a change in the workload fails here until the screen follows it.
 */
describe('source excerpts on the visitor screens', () => {
  it('match the workload source line for line', () => {
    for (const excerpt of ADOPT_CODE) {
      const source = readFileSync(`../${excerpt.path}`, 'utf-8').replace(/\r\n/g, '\n');
      expect(source, excerpt.path).toContain(excerpt.lines.join('\n'));
    }
  });
});
