import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { BenchmarkEngine } from '../../api/benchmark';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import BenchReasoningPage from './BenchReasoningPage';
import { benchmark, stubFetch } from './benchFixture';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

let answer: { readonly status: number; readonly body: unknown };

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal('fetch', vi.fn(stubFetch(() => ({ '/api/benchmark': answer }))));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/benchmark/reasoning']}>
        <Routes>
          <Route path="*" element={<BenchReasoningPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** A portal with BM-S6: the explanations by truth, the retries and their reasons, one answer that moved. */
function withReasoning() {
  const base = benchmark();
  const engine = required(base.engine, 'the engine');
  // A portal of the review (V-46) also sends the decisions by the action each applied.
  const reasoning = {
    mostLikely: { THREAT: { H2: 16, H1: 3, NONE: 1 }, NORMAL: { H1: 7 }, UNCERTAIN: { H1: 2, H3: 1 } },
    mostLikelyActions: {
      THREAT: { H1: { ALLOW: 1, CHALLENGE: 2 }, H2: { BLOCK: 16 }, NONE: { CHALLENGE: 1 } },
      NORMAL: { H1: { ALLOW: 7 } },
      UNCERTAIN: { H1: { ALLOW: 2 }, H3: { BLOCK: 1 } },
    },
    retried: 4,
    retryKinds: { REASON_CODE_MISMATCH: 4 },
    topRetryReasons: [
      {
        reason: 'PAST_RECORD_SAME_TARGET P# (the code does not cite PAST_RECORDS.PastRecordCounts)',
        decisions: 3,
      },
    ],
    flips: { 'CHALLENGE->ALLOW': 1 },
  };
  const reasoned: BenchmarkEngine = {
    ...engine,
    agreement: { decisions: 12, modelAnswered: 10, asAnswered: 10, technical: 0, held: 2 },
    reasoning,
  };
  return { ...base, engine: reasoned };
}

/** B-5 of docs/showcase/벤치마크-구현계획.md: whether the AI's judgment can be trusted, in the portal's counts. */
describe('benchmark reasoning', () => {
  it('draws the explanation each decision judged most likely by truth, with the model-answer and retry lines', async () => {
    answer = { status: 200, body: withReasoning() };
    const { container } = open();
    expect(
      await screen.findByRole('img', { name: word('bench.chart.reasoning.summary') }),
    ).toBeInTheDocument();
    // V-26 of docs/showcase/영상전-검토.md: the decisions told apart from the runs, first.
    expect(
      screen.getByText(fill('bench.chart.reasoning.scope', { runs: 105, decisions: 120 })),
    ).toBeInTheDocument();
    // R-09: the open situations' decisions are a row too, so the rows add up to every decision answered.
    expect(
      Array.from(
        container.querySelectorAll<HTMLElement>('[role="img"] [data-row]'),
        (row) => row.dataset.row,
      ),
    ).toEqual(['THREAT', 'NORMAL', 'UNCERTAIN']);
    // P-22: a wide segment says its explanation in words, never "H2 6"; B-15: the small ones are named under the bar.
    const threat = required(container.querySelector<HTMLElement>('[data-row="THREAT"]'), 'the attack row');
    expect(threat.querySelector('[data-kind="H2"]')).toHaveTextContent(
      `${word('bench.chart.reasoning.explanation.H2')} 16`,
    );
    expect(container.querySelector('[data-row="NORMAL"] [data-kind="H1"]')).toHaveTextContent(
      `${word('bench.chart.reasoning.explanation.H1')} 7`,
    );
    expect(threat).not.toHaveTextContent('H2');
    expect(threat.querySelector('[data-small="THREAT"]')).toHaveTextContent(
      fill('bench.chart.stack.small', {
        items: fill('bench.chart.stack.item', {
          label: word('bench.chart.reasoning.explanation.NONE'),
          n: 1,
        }),
      }),
    );
    // B-15: every kind of the legend has a swatch, and how to read the bar comes before it, as a line.
    const legend = required(container.querySelector('figure ul'), 'the legend');
    for (const item of Array.from(legend.querySelectorAll('li'))) {
      expect(item.querySelector('[data-tone]:not(li)')).not.toBeNull();
    }
    const read = screen.getByText(word('bench.chart.reasoning.read'));
    expect(
      read.compareDocumentPosition(required(container.querySelector('figure'), 'the bar')) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    // V-46: the attack decisions that judged legitimate work most likely, by the action each still took.
    expect(
      screen.getByText(
        fill('bench.chart.reasoning.h1Threat', {
          n: 3,
          actions: [
            fill('bench.chart.reasoning.action', { verdict: word('verdict.allow'), n: 1 }),
            fill('bench.chart.reasoning.action', { verdict: word('verdict.verify'), n: 2 }),
          ].join(' · '),
        }),
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(fill('bench.r7.proof.agreement', { as: 10, answered: 10, technical: 0, held: 2 })),
    ).toBeInTheDocument();
    expect(screen.getByText(fill('bench.chart.reasoning.retried', { n: 4 }))).toBeInTheDocument();
    expect(
      screen.getByText(
        fill('bench.chart.reasoning.flip', { from: word('verdict.verify'), to: word('verdict.allow'), n: 1 }),
      ),
    ).toBeInTheDocument();
    const reasons = screen.getByRole('region', { name: word('bench.chart.reasoning.reasons') });
    expect(
      within(reasons).getByText(
        'PAST_RECORD_SAME_TARGET P# (the code does not cite PAST_RECORDS.PastRecordCounts)',
      ),
    ).toHaveAttribute('data-original');
  });

  it('says so from a portal without the count, and walks between judgment and limits', async () => {
    answer = { status: 200, body: benchmark() };
    open();
    expect(await screen.findByText(word('bench.chart.reasoning.none'))).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('frame.back') })).toHaveAttribute(
      'href',
      '/benchmark/judgment',
    );
    expect(screen.getByRole('link', { name: word('bench.r7.next.limits') })).toHaveAttribute(
      'href',
      '/benchmark/limits',
    );
  });
});
