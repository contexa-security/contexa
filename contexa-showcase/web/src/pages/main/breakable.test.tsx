import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { breakable } from './breakable';

describe('an engine name that breaks only at its own joints', () => {
  it('keeps the words and lets them break after an underscore', () => {
    const { container } = render(<code>{breakable('POLICY_NOT_SATISFIED')}</code>);
    expect(container.textContent).toBe('POLICY_NOT_SATISFIED');
    expect(container.querySelectorAll('wbr')).toHaveLength(2);
  });

  it('lets a camel-case name break before each new word only', () => {
    const { container } = render(<code>{breakable('F1 DeviationsFromBaseline')}</code>);
    expect(container.textContent).toBe('F1 DeviationsFromBaseline');
    expect(container.querySelectorAll('wbr')).toHaveLength(2);
  });
});
