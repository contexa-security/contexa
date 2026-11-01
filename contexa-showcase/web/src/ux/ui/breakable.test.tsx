import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { breakable } from './breakable';

/** The pieces a line may break between, as rendered (the text between the break opportunities). */
function pieces(text: string): string[] {
  const { container } = render(<code>{breakable(text)}</code>);
  const code = container.querySelector('code');
  const out: string[] = [];
  let current = '';
  code?.childNodes.forEach((node) => {
    if (node.nodeName === 'WBR') {
      out.push(current);
      current = '';
    } else {
      current += node.textContent ?? '';
    }
  });
  out.push(current);
  return out;
}

describe('a machine name that breaks at its parts', () => {
  it('breaks after a separator and before a capital, never leaving one character alone', () => {
    expect(pieces('important_instructions')).toEqual(['important_', 'instructions']);
    expect(pieces('FacebookManagerGetUserProfile')).toEqual([
      'Facebook',
      'Manager',
      'Get',
      'User',
      'Profile',
    ]);
    expect(pieces('claude-sonnet-5-5')).toEqual(['claude-', 'sonnet-', '5-5']);
    expect(pieces('contexa-injecagent-v1')).toEqual(['contexa-', 'injecagent-', 'v1']);
    expect(pieces('S13')).toEqual(['S13']);
  });
});
