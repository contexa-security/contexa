import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PromptQualityView } from '../../api/promptQuality';
import '../../i18n';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import BenchPromptPage from './BenchPromptPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

function rate(hits: number, total: number, low: number, high: number, preliminary = false) {
  return { hits, total, rate: hits / total, low, high, preliminary };
}

/** A published batch as the portal's prompt-quality view gives it (the numbers are this test's own). */
const view: PromptQualityView = {
  measuredAt: '2026-10-16T05:40:00Z',
  setting: 'a'.repeat(64),
  batch: 'batch-p7-1',
  protocol: 'protocol-p7-1',
  delivery: rate(10, 11, 0.623, 0.984),
  reaction: {
    direction: rate(99, 122, 0.733, 0.87),
    minimumKept: rate(40, 40, 0.912, 1),
    consistency: rate(110, 122, 0.838, 0.944),
  },
  invariance: {
    firstStepFacts: rate(26, 26, 0.871, 1),
    decisions: rate(37, 39, 0.832, 0.986),
    decisionChanges: 2,
  },
  injection: { changed: 1, unchanged: rate(3, 4, 0.301, 0.954, true) },
  accuracy: rate(950, 960, 0.981, 0.995),
  consistency: rate(37, 39, 0.832, 0.986),
  reasonMatch: rate(88, 90, 0.923, 0.994),
};

let answer: { readonly status: number; readonly body: unknown };

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const { status, body } = url.startsWith('/api/benchmark/prompt-quality')
        ? answer
        : { status: 404, body: null };
      return new Response(body === null ? null : JSON.stringify(body), { status });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
}

function open(path = '/benchmark/prompt') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={<BenchPromptPage />} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** U-6, C-23: the benchmark's prompt-quality tab. */
describe('prompt quality tab', () => {
  it('says nothing is measured yet while the server has no published batch (404)', async () => {
    answer = { status: 404, body: null };
    open();
    expect(await screen.findByText(word('promptQuality.notMeasured'))).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('promptQuality.title'));
    expect(screen.queryByRole('region', { name: word('promptQuality.cards') })).not.toBeInTheDocument();
    // The tab is the current view of the benchmark's band, after "judgment and timing".
    const views = screen.getByRole('list', { name: word('benchBar.views') });
    const names = within(views)
      .getAllByRole('link')
      .map((link) => link.textContent);
    expect(names.indexOf(word('benchBar.view.prompt'))).toBe(names.indexOf(word('benchBar.view.judgment')) + 1);
    expect(within(views).getByRole('link', { name: word('benchBar.view.prompt') })).toHaveAttribute(
      'aria-current',
      'page',
    );
  });

  it("shows the four big numbers and the other three with their samples, 95% intervals and the measured date", async () => {
    answer = { status: 200, body: view };
    open();
    const cards = await screen.findByRole('region', { name: word('promptQuality.cards') });
    const card = (name: string) => required(cards.querySelector(`[data-card="${name}"]`), name);
    expect(card('delivery')).toHaveTextContent('10/11');
    expect(card('delivery')).toHaveTextContent(fill('benchmark.interval', { low: '62.3%', high: '98.4%' }));
    expect(card('reaction')).toHaveTextContent('81.1%');
    expect(card('reaction')).toHaveTextContent(fill('promptQuality.sample', { n: '99/122' }));
    // Invariance: the decision changes as the big number, the unchanged facts as its denominator line.
    expect(card('invariance')).toHaveTextContent(fill('promptQuality.card.invariance.value', { n: 2 }));
    expect(card('invariance')).toHaveTextContent(fill('promptQuality.unchanged', { n: '26/26' }));
    // Injection: the changed decisions over the injected variants, then the unchanged ones.
    expect(card('injection')).toHaveTextContent(fill('promptQuality.card.injection.value', { n: 1, total: 4 }));
    expect(card('injection')).toHaveTextContent(fill('promptQuality.unchanged', { n: '3/4' }));
    expect(card('injection')).toHaveTextContent(word('benchmark.preliminary'));
    expect(card('delivery')).not.toHaveTextContent(word('benchmark.preliminary'));
    const more = screen.getByRole('list', { name: word('promptQuality.more') });
    expect(more).toHaveTextContent(fill('promptQuality.more.accuracy', { rate: '99%' }));
    expect(more).toHaveTextContent(fill('promptQuality.sample', { n: '950/960' }));
    expect(more).toHaveTextContent(fill('promptQuality.more.reasonMatch', { rate: '97.8%' }));
    expect(more).toHaveTextContent(fill('promptQuality.more.consistency', { rate: '94.9%' }));
    // Every number has its interval: four cards and three lines.
    expect(screen.getAllByText(/95%/)).toHaveLength(7);
    expect(screen.getByText(fill('promptQuality.measured', { date: '2026-10-16' }))).toBeInTheDocument();
  });

  it('opens how it was measured in its own window, with the numbers measured alongside', async () => {
    answer = { status: 200, body: view };
    open();
    await userEvent.click(await screen.findByRole('button', { name: word('promptQuality.method') }));
    expect(screen.getByTestId('where')).toHaveTextContent('modal=prompt-method');
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent(word('promptQuality.method.delivery'));
    expect(dialog).toHaveTextContent(fill('promptQuality.method.minimumKept', { value: '40/40' }));
    expect(within(dialog).getByText('batch-p7-1')).toHaveAttribute('data-original');
  });
});
