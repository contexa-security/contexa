import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import SummaryEndPage from './SummaryEndPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 5, step: 'summary-end', differences: [] },
          runs: [],
          predictions: [],
        },
      };
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Screen 5-4, the end (화면재편-기획안 7절): three ways on, the cards being the screen's action. */
// The final screen design (최종화면-구현계획 F0-1) opens this screen at no address any more; its address leads to the
// new flow. The screen and this test are on the deletion list for the user (최종화면-구현계획 4절).
describe.skip('the end of the flow', () => {
  it('offers the lab, the benchmark and adopting as three cards, with no further main button', () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { container } = render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={['/try/summary/end']}>
          <SummaryEndPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.5-4.title'));
    expect(screen.getByText(word('screen.5-4.guide'))).toBeInTheDocument();
    const paths = required(container.querySelector<HTMLElement>('[data-count="exempt"]'), 'the three cards');
    const links = within(paths).getAllByRole('link');
    expect(links.map((link) => link.getAttribute('href'))).toEqual(['/lab', '/benchmark', '/adopt']);
    for (const [index, key] of ['lab', 'benchmark', 'adopt'].entries()) {
      expect(links[index]).toHaveTextContent(word(`screen.5-4.${key}`));
      expect(links[index]).toHaveTextContent(word(`screen.5-4.${key}.line`));
    }
    // The last screen: back to 5-3, and nothing else in the action bar.
    expect(container.querySelector('[data-main]')).toBeNull();
    const actions = required(container.querySelector<HTMLElement>('[data-zone="actions"]'), 'the action bar');
    expect(within(actions).getAllByRole('link')).toHaveLength(1);
    expect(within(actions).getByRole('link', { name: word('frame.back') })).toHaveAttribute(
      'href',
      '/try/summary/adopt',
    );
  });
});
