import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import MorePage from './MorePage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 8, step: 'next', differences: [] },
          runs: [],
          predictions: [],
        },
      };
      const body = bodies[url];
      return Promise.resolve(
        new Response(body === undefined ? null : JSON.stringify(body), { status: body === undefined ? 404 : 200 }),
      );
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/more']}>
        <MorePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The hub of "learn more" (최종화면-구현계획 F0-7): one card per topic, in the design's order. */
describe('the learn-more hub', () => {
  it("names each topic's card by what its screens show; adoption in the order of its three steps", () => {
    open();
    const cards = screen.getAllByRole('link');
    const topics = ['learning', 'timing', 'follow', 'approaches', 'lab', 'benchmark', 'adopt'];
    expect(cards.filter((card) => card.closest('ul'))).toHaveLength(topics.length);
    for (const topic of topics) {
      const card = required(screen.getByText(word(`more.topic.${topic}`)).closest('a'), topic);
      expect(within(card).getByText(word(`more.topic.${topic}.line`))).toBeInTheDocument();
    }
    // V-55: the adoption card promises what the adoption screen shows, in its order.
    const line = word('more.topic.adopt.line');
    const steps = ['space.r7.adopt.change.step', 'space.r7.adopt.attach.step', 'space.r7.adopt.on.step'].map(word);
    expect(steps.map((step) => line.indexOf(step))).toEqual([...steps.map((step) => line.indexOf(step))].sort((a, b) => a - b));
    for (const step of steps) {
      expect(line).toContain(step);
    }
  });

  it('draws no footer band: the hub has no way back, next screen or main button to hold (B-05)', () => {
    const { container } = open();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('more.title'));
    expect(screen.getByText(word('more.intro'))).toBeInTheDocument();
    expect(container.querySelector('[data-zone="body"] ul')).not.toBeNull();
    expect(container.querySelector('[data-zone="actions"]')).toBeNull();
    expect(container.querySelector('main nav')).toBeNull();
  });
});
