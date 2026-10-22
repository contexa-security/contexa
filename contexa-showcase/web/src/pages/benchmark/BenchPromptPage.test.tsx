import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { promptQualityRawHref, type PromptQualityView } from '../../api/promptQuality';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { stubFetch } from './benchFixture';
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

/** A published record as the portal's prompt-quality view gives it (the numbers are this test's own). */
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
  vi.stubGlobal('fetch', vi.fn(stubFetch(() => ({ '/api/benchmark/prompt-quality': answer }))));
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

function row(name: string): HTMLElement {
  return required(document.querySelector<HTMLElement>(`tr[data-row="${name}"]`), name);
}

function range(low: string, high: string): string {
  return fill('bench.r7.rangeValue', { low, high });
}

/** The text sent to the AI (화면재편-구현계획 RO-3, a table view; U-6, C-23). */
describe('benchmark text sent to the AI', () => {
  it('says there is nothing to show yet while the server has no published record (404)', async () => {
    answer = { status: 404, body: null };
    const { container } = open();
    expect(await screen.findByText(word('bench.r7.prompt.notMeasured'))).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('bench.r7.prompt.title'));
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
    // Nothing published: no record to download, no window to open.
    expect(screen.queryByRole('button', { name: word('frame.source.open') })).not.toBeInTheDocument();
  });

  it('shows the seven values in one table with what each checks, its sample and its range', async () => {
    answer = { status: 200, body: view };
    const { container } = open();
    await screen.findByRole('table');
    expect(container.querySelector('main')).toHaveAttribute('data-type', 'table');
    expect(
      Array.from(document.querySelectorAll<HTMLElement>('tr[data-row]'), (element) => element.dataset.row),
    ).toEqual(['delivery', 'reaction', 'invariance', 'injection', 'accuracy', 'reasonMatch', 'consistency']);
    expect(row('delivery')).toHaveTextContent(word('bench.r7.prompt.row.delivery'));
    expect(row('delivery')).toHaveTextContent('10/11');
    expect(row('delivery')).toHaveTextContent(word('bench.r7.prompt.row.delivery.what'));
    expect(row('delivery')).toHaveTextContent(range('62.3%', '98.4%'));
    expect(row('reaction')).toHaveTextContent('81.1%');
    expect(row('reaction')).toHaveTextContent(fill('bench.r7.prompt.sample', { n: '99/122' }));
    // Invariance: the judgments that changed as the value, the unchanged facts as its sample.
    expect(row('invariance')).toHaveTextContent(fill('bench.r7.prompt.invariance.value', { n: 2 }));
    expect(row('invariance')).toHaveTextContent(fill('bench.r7.prompt.unchanged', { n: '26/26' }));
    expect(row('injection')).toHaveTextContent(fill('bench.r7.prompt.injection.value', { n: 1, total: 4 }));
    expect(row('injection')).toHaveTextContent(fill('bench.r7.prompt.unchanged', { n: '3/4' }));
    // "Few runs yet" only where the server says the sample is small.
    expect(row('injection')).toHaveTextContent(word('bench.r7.preliminary'));
    expect(row('delivery')).not.toHaveTextContent(word('bench.r7.preliminary'));
    expect(row('accuracy')).toHaveTextContent('99%');
    expect(row('accuracy')).toHaveTextContent(fill('bench.r7.prompt.sample', { n: '950/960' }));
    expect(row('reasonMatch')).toHaveTextContent('97.8%');
    expect(row('consistency')).toHaveTextContent('94.9%');
    expect(
      screen.getByRole('columnheader', { name: word('bench.r7.prompt.column.range') }),
    ).toBeInTheDocument();
  });

  it('scrolls the table sideways inside its own region, reached by the keyboard (U6-7)', async () => {
    answer = { status: 200, body: view };
    open();
    const region = await screen.findByRole('region', { name: word('bench.r7.prompt.caption') });
    expect(region).toHaveAttribute('tabindex', '0');
    expect(region).toContainElement(screen.getByRole('table'));
    // How the region scrolls at phone width is the stylesheets' (benchPromptPhone.test.ts).
  });

  it('keeps one thing to press in the body: the source line with the record date opening how it was made', async () => {
    answer = { status: 200, body: view };
    const { container } = open();
    await screen.findByRole('table');
    const zones = Array.from(
      container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'),
    );
    const pressables = zones.flatMap((zone) =>
      Array.from(zone.querySelectorAll('button, a[href], select, summary')),
    );
    expect(pressables.map((element) => element.textContent)).toEqual([word('frame.source.open')]);
    expect(required(container.querySelector('[data-zone="source"]'), 'the source line')).toHaveTextContent(
      fill('bench.r7.prompt.source', { date: '2026-10-16' }),
    );
    expect(screen.getByRole('link', { name: word('frame.back') })).toHaveAttribute(
      'href',
      '/benchmark/judgment',
    );
    expect(screen.getByRole('link', { name: word('bench.r7.next.limits') })).toHaveAttribute(
      'href',
      '/benchmark/limits',
    );
  });

  it('opens how the record was made in its own window, with the values made alongside and the download', async () => {
    answer = { status: 200, body: view };
    open();
    await userEvent.click(await screen.findByRole('button', { name: word('frame.source.open') }));
    expect(screen.getByTestId('where')).toHaveTextContent('modal=prompt-method');
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent(word('bench.r7.prompt.method.delivery'));
    expect(dialog).toHaveTextContent(fill('bench.r7.prompt.method.minimumKept', { value: '40/40' }));
    expect(within(dialog).getByText('batch-p7-1')).toHaveAttribute('data-original');
    const raw = within(dialog).getByRole('link', { name: word('bench.r7.raw') });
    expect(raw).toHaveAttribute('href', `/api/benchmark/prompt-quality?setting=${'a'.repeat(64)}&raw=true`);
    expect(raw).toHaveAttribute('download', 'contexa-prompt-quality.json');
  });

  it('names the record batch of each value when they come from batches of their own (N-PQ-1)', async () => {
    answer = {
      status: 200,
      body: {
        ...view,
        batch: null,
        batches: { delivery: 'p8-delivery', reaction: 'p8-reaction', injection: 'p8-injection' },
      },
    };
    open();
    await userEvent.click(await screen.findByRole('button', { name: word('frame.source.open') }));
    const dialog = screen.getByRole('dialog');
    for (const batch of ['p8-delivery', 'p8-reaction', 'p8-injection']) {
      expect(within(dialog).getByText(batch)).toHaveAttribute('data-original');
    }
  });

  it('shows the earlier record against this one, as the server counted both (U6-4)', async () => {
    answer = {
      status: 200,
      body: {
        ...view,
        comparison: {
          baselineProtocol: 'protocol-v19',
          baselineBundle: '2026.10.16-v19.20',
          bundle: '2026.10.16-v20.24',
          attackBefore: rate(67, 90, 0.64, 0.82),
          attackNow: rate(80, 80, 0.95, 1),
          normalBefore: rate(8, 66, 0.06, 0.22),
          normalNow: rate(2, 75, 0.01, 0.09),
        },
      },
    };
    open();
    expect(
      await screen.findByText(
        fill('promptQuality.comparison', {
          before: 'v19.20',
          now: 'v20.24',
          attackBefore: '67/90',
          attackNow: '80/80',
          normalBefore: '8/66',
          normalNow: '2/75',
        }),
      ),
    ).toBeInTheDocument();
  });

  it('gives the raw data an address of its own, apart from what the view reads (U6-5)', () => {
    expect(promptQualityRawHref('a'.repeat(64))).toBe(
      `/api/benchmark/prompt-quality?setting=${'a'.repeat(64)}&raw=true`,
    );
    expect(promptQualityRawHref(null)).toBe('/api/benchmark/prompt-quality?raw=true');
  });
});
