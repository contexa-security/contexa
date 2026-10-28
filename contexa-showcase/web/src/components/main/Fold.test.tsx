import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { Fold } from './Fold';

describe('a layer of a screen', () => {
  it('opens itself when told to, and the visitor can still close it', async () => {
    const user = userEvent.setup();
    const { container, rerender } = render(
      <Fold name="example" summary="More" open={false}>
        <p>The rest</p>
      </Fold>,
    );
    const fold = container.querySelector('details') as HTMLDetailsElement;
    expect(fold.open).toBe(false);
    rerender(
      <Fold name="example" summary="More" open>
        <p>The rest</p>
      </Fold>,
    );
    expect(fold.open).toBe(true);
    await user.click(screen.getByText('More'));
    expect(fold.open).toBe(false);
  });

  it('is closed at first, named for the checks, and keeps what it holds in the page', () => {
    const { container } = render(
      <Fold name="example" summary="More">
        <p>The rest of the facts</p>
      </Fold>,
    );
    const fold = container.querySelector('details[data-fold="example"]') as HTMLDetailsElement;
    expect(fold.open).toBe(false);
    expect(screen.getByText('More').tagName).toBe('SUMMARY');
    expect(fold).toContainElement(screen.getByText('The rest of the facts'));
  });

  it('takes the focus on its summary line and opens with a press, the key press itself being the browser own and checked by the keyboard e2e', async () => {
    const user = userEvent.setup();
    const { container } = render(
      <Fold name="example" summary="More">
        <p>The rest</p>
      </Fold>,
    );
    await user.tab();
    expect(screen.getByText('More')).toHaveFocus();
    await user.click(screen.getByText('More'));
    expect((container.querySelector('details') as HTMLDetailsElement).open).toBe(true);
  });
});
