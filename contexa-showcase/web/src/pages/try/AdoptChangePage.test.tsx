import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../../i18n';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import AdoptChangePage from './AdoptChangePage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

interface Engine {
  readonly analysisP50Ms: number | null;
  readonly analysisP95Ms: number | null;
  readonly costPerDecisionUsd: number | null;
  readonly tokensPerDecision: number | null;
}

/** Two measurements with different values, so a cell that shows a constant fails one of them. */
const RECORDS = [
  {
    name: 'a priced measurement',
    engine: {
      analysisP50Ms: 3760,
      analysisP95Ms: 7249,
      costPerDecisionUsd: 0.00043,
      tokensPerDecision: 7629.4,
    },
    time: { p50: '3.8', p95: '7.2' },
    cost: { usd: '0.0004', tokens: '7,629' },
  },
  {
    name: 'a slower, dearer measurement',
    engine: {
      analysisP50Ms: 12000,
      analysisP95Ms: 20500,
      costPerDecisionUsd: 0.0123,
      tokensPerDecision: 1200,
    },
    time: { p50: '12.0', p95: '20.5' },
    cost: { usd: '0.01', tokens: '1,200' },
  },
] as const;

let answer: { readonly status: number; readonly body: unknown };

function measured(engine: Engine) {
  return { status: 200, body: { engine, controls: [], suites: [] } };
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, { readonly status: number; readonly body: unknown }> = {
        '/api/benchmark': answer,
        '/api/visitor': { status: 200, body: { predictions: {} } },
        '/api/journey': {
          status: 200,
          body: {
            state: { route: 'DEFAULT', act: 5, step: 'adopt-change', differences: [] },
            runs: [],
            predictions: [],
          },
        },
      };
      const { status, body } = bodies[url] ?? { status: 404, body: null };
      return new Response(body === null ? null : JSON.stringify(body), { status });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/try/summary/adopt']}>
        <AdoptChangePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function cells(container: HTMLElement): readonly { readonly name: string; readonly value: string }[] {
  const list = container.querySelector('[data-zone="body"] dl');
  return Array.from(required(list, 'the cells').querySelectorAll(':scope > div'), (cell) => ({
    name: cell.querySelector('dt')?.textContent ?? '',
    value: cell.querySelector('dd')?.textContent ?? '',
  }));
}

/** Screen 5-3 (화면재편-기획안 7절, T7): four cells, the time and the cost the benchmark's measurement. */
// The final screen design (최종화면-구현계획 F0-1) opens this screen at no address any more; its address leads to the
// new flow. The screen and this test are on the deletion list for the user (최종화면-구현계획 4절).
describe.skip('what changes when you adopt it', () => {
  it.each(RECORDS)(
    'shows the code line, the flow, and the time and cost as measured ($name)',
    async (record) => {
      answer = measured(record.engine);
      const { container } = open();
      await screen.findByText(fill('p5.adopt.time', { ...record.time, mode: word('timing.mode.sync') }));
      expect(cells(container).map((cell) => cell.name)).toEqual(
        ['code', 'flow', 'time', 'cost'].map((cell) => word(`adoptChange.name.${cell}`)),
      );
      expect(screen.getByText(fill('p5.adopt.cost', record.cost))).toBeInTheDocument();
      expect(screen.getByText(word('p5.adopt.flow'))).toBeInTheDocument();
      // The code is shown as code, kept apart from the screen's words and numbers.
      const code = screen.getByText('@Protectable');
      expect(code.tagName).toBe('CODE');
      expect(code).toHaveAttribute('data-original');
    },
  );

  it('leaves the other four cells to the adopt screen', async () => {
    answer = measured(RECORDS[0].engine);
    open();
    await screen.findByText(fill('p5.adopt.cost', RECORDS[0].cost));
    const text = document.body.textContent ?? '';
    for (const cell of ['data', 'employee', 'admin', 'start']) {
      expect(text, cell).not.toContain(word(`adoptChange.name.${cell}`));
    }
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.5-3.title'));
    expect(screen.getByRole('link', { name: word('screen.5-3.next') })).toHaveAttribute(
      'href',
      '/try/summary/end',
    );
  });

  it('says what the measurement does not hold instead of a number', async () => {
    answer = measured({
      analysisP50Ms: null,
      analysisP95Ms: null,
      costPerDecisionUsd: null,
      tokensPerDecision: null,
    });
    open();
    expect(await screen.findByText(word('p5.adopt.timeNone'))).toBeInTheDocument();
    expect(screen.getByText(word('adoptChange.value.costNone'))).toBeInTheDocument();
  });

  it('names the cost alone when the tokens per judgment are not counted', async () => {
    answer = measured({ ...RECORDS[0].engine, tokensPerDecision: null });
    open();
    expect(await screen.findByText(fill('p5.adopt.costOnly', { usd: '0.0004' }))).toBeInTheDocument();
  });

  it('keeps one source line while the measurement is there, and none without it', async () => {
    answer = measured(RECORDS[0].engine);
    const first = open();
    await screen.findByText(fill('p5.adopt.cost', RECORDS[0].cost));
    const source = required(
      first.container.querySelector<HTMLElement>('[data-zone="source"]'),
      'the source line',
    );
    expect(source).toHaveTextContent(word('frame.source.measured'));
    const zones = Array.from(
      first.container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'),
    );
    expect(zones.flatMap((zone) => Array.from(zone.querySelectorAll('button, a[href]')))).toHaveLength(0);
    first.unmount();

    answer = { status: 404, body: null };
    const second = open();
    expect(await within(second.container).findByText(word('p5.adopt.timeNone'))).toBeInTheDocument();
    expect(second.container.querySelector('[data-zone="source"]')).toBeNull();
  });
});
