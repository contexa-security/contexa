import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { benchCase, benchmark, stubFetch } from './benchFixture';
import BenchJudgmentPage from './BenchJudgmentPage';

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

function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
}

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/benchmark/judgment']}>
        <Routes>
          <Route path="*" element={<BenchJudgmentPage />} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function legend(kind: string): HTMLElement {
  return required(document.querySelector<HTMLElement>(`li[data-kind="${kind}"]`), kind);
}

/** Two records with different counts, so a view that shows a constant fails one of them. */
const RECORDS = [
  {
    name: 'nothing else',
    timing: { STATIC_REFUSAL: 5, BEFORE_RESPONSE: 25, NEXT_REQUEST: 10, JUDGED_ALLOW: 3, OTHER: 0 },
    attackRuns: 55,
    risk: { runs: 46, stopped: 44 },
  },
  {
    name: 'some other ending',
    timing: { STATIC_REFUSAL: 1, BEFORE_RESPONSE: 7, NEXT_REQUEST: 0, JUDGED_ALLOW: 12, OTHER: 4 },
    attackRuns: 24,
    risk: { runs: 9, stopped: 7 },
  },
] as const;

/** Judgment and timing (화면재편-구현계획 RO-3, a table view): the server's count of how each attack ended. */
describe('benchmark judgment and timing', () => {
  it.each(RECORDS)('counts each way the attacks ended as the server did ($name)', async (record) => {
    answer = {
      status: 200,
      body: benchmark({
        judgmentTiming: record.timing,
        riskJudged: record.risk,
        scope: { ...benchmark().scope, attackRuns: record.attackRuns },
      }),
    };
    const { container } = open();
    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: fill('bench.r7.judgment.title', { n: record.attackRuns }),
      }),
    ).toBeInTheDocument();
    expect(container.querySelector('main')).toHaveAttribute('data-type', 'table');
    for (const kind of ['STATIC_REFUSAL', 'BEFORE_RESPONSE', 'NEXT_REQUEST', 'JUDGED_ALLOW'] as const) {
      expect(legend(kind)).toHaveTextContent(word(`bench.r7.judgment.kind.${kind}`));
      expect(legend(kind)).toHaveTextContent(fill('benchmark.times', { n: record.timing[kind] }));
    }
    // "Other" shows only when the server counted some.
    expect(document.querySelector('li[data-kind="OTHER"]') !== null).toBe(record.timing.OTHER > 0);
    expect(
      screen.getByText(fill('bench.r7.judgment.timing', { n: record.timing.NEXT_REQUEST })),
    ).toBeInTheDocument();
    expect(
      screen.getByText(fill('bench.r7.judgment.judged', { n: record.timing.JUDGED_ALLOW })),
    ).toBeInTheDocument();
    expect(screen.getByText(fill('bench.r7.judgment.risk', record.risk))).toBeInTheDocument();
  });

  // V-01 of docs/showcase/영상전-검토.md: the record of 2026-10-20 (protocol-7b925e8e), its two "other" runs as the
  // portal sends them.
  it("words each 'other' run step by step from the server and names the bars the risky runs sit in", async () => {
    const base = benchmark({
      cases: [benchCase('S11', 'THREAT', {}), benchCase('S19', 'THREAT', {})],
      judgmentTiming: { STATIC_REFUSAL: 1, BEFORE_RESPONSE: 6, NEXT_REQUEST: 13, JUDGED_ALLOW: 1, OTHER: 2 },
      judgmentExposure: {
        STATIC_REFUSAL: 0,
        BEFORE_RESPONSE: 0,
        NEXT_REQUEST: 7276,
        JUDGED_ALLOW: 300,
        OTHER: 483,
      },
      scope: { ...benchmark().scope, attackRuns: 23 },
    });
    answer = {
      status: 200,
      body: {
        ...base,
        riskJudged: {
          runs: 21,
          stopped: 20,
          kinds: { STATIC_REFUSAL: 0, BEFORE_RESPONSE: 6, NEXT_REQUEST: 13, JUDGED_ALLOW: 0, OTHER: 2 },
          notStopped: ['S19'],
        },
        judgmentOthers: [
          {
            runId: 'run-87c7bd071cb8',
            caseKey: 'S11',
            result: 'PARTLY_STOPPED',
            exposedItems: 480,
            steps: [
              { stepNo: 1, action: 'ALLOW', applied: 'BEFORE_RESPONSE', source: 'MODEL', applicable: true },
              { stepNo: 2, action: 'BLOCK', applied: 'BEFORE_RESPONSE', source: 'MODEL', applicable: true },
              { stepNo: 3, action: null, applied: 'NONE', source: 'PRIOR_DECISION', applicable: false },
              { stepNo: 4, action: null, applied: 'NONE', source: 'PRIOR_DECISION', applicable: false },
              { stepNo: 5, action: null, applied: 'NONE', source: 'PRIOR_DECISION', applicable: false },
            ],
          },
          {
            runId: 'run-8d9e43b2882e',
            caseKey: 'S19',
            result: 'MISSED',
            exposedItems: 3,
            steps: [
              { stepNo: 1, action: 'ALLOW', applied: 'NEXT_REQUEST', source: 'MODEL', applicable: true },
              { stepNo: 2, action: null, applied: 'NONE', source: 'NOT_ANALYSED', applicable: false },
              { stepNo: 3, action: 'CHALLENGE', applied: 'NEXT_REQUEST', source: 'MODEL', applicable: false },
            ],
          },
        ],
      },
    };
    open();
    const others = await screen.findByRole('list', {
      name: fill('bench.r7.judgment.othersTitle', { count: 2 }),
    });
    const lines = within(others).getAllByRole('listitem');
    expect(lines.map((line) => line.textContent)).toEqual([
      fill('bench.r7.judgment.other', {
        name: word('bench.r7.caseName.S11'),
        steps: [
          fill('bench.r7.judgment.step.decided', {
            n: 1,
            verdict: word('verdict.allow'),
            applied: word('bench.r7.judgment.applied.BEFORE_RESPONSE'),
          }),
          fill('bench.r7.judgment.step.decided', {
            n: 2,
            verdict: word('verdict.block'),
            applied: word('bench.r7.judgment.applied.BEFORE_RESPONSE'),
          }),
          fill('bench.r7.judgment.step.PRIOR_DECISION', { n: '3~5' }),
        ].join(' · '),
        result: word('main.result.PARTLY_STOPPED'),
        items: 480,
      }),
      fill('bench.r7.judgment.other', {
        name: word('bench.r7.caseName.S19'),
        steps: [
          fill('bench.r7.judgment.step.decided', {
            n: 1,
            verdict: word('verdict.allow'),
            applied: word('bench.r7.judgment.applied.NEXT_REQUEST'),
          }),
          fill('bench.r7.judgment.step.NOT_ANALYSED', { n: 2 }),
          fill('bench.r7.judgment.step.decided', {
            n: 3,
            verdict: word('verdict.verify'),
            applied: word('bench.r7.judgment.applied.late'),
          }),
        ].join(' · '),
        result: word('main.result.MISSED'),
        items: 3,
      }),
    ]);
    // The risky runs as the bars hold them: 6 + 13 + 2, and the one not stopped named.
    const kind = (key: string, n: number) =>
      fill('bench.r7.judgment.riskKind', { kind: word(`bench.r7.judgment.kind.${key}`), n });
    expect(
      screen.getByText(
        fill('bench.r7.judgment.riskKinds', {
          runs: 21,
          stopped: 20,
          kinds: [kind('BEFORE_RESPONSE', 6), kind('NEXT_REQUEST', 13), kind('OTHER', 2)].join(' · '),
        }),
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(fill('bench.r7.judgment.notStopped', { cases: word('bench.r7.caseName.S19') })),
    ).toBeInTheDocument();
    // V-24: the items that left in those runs, before and after a decision, as leaked items.
    expect(
      screen.getByText(
        fill('bench.chart.judgment.exposed', {
          kind: word('bench.r7.judgment.kind.JUDGED_ALLOW'),
          items: 300,
        }),
      ),
    ).toBeInTheDocument();
    // V-65: the time chart counts every decision, not the 23 attacks of the title.
    expect(
      screen.getByRole('heading', { level: 2, name: fill('bench.chart.judgment.timeTitle', { n: 120 }) }),
    ).toBeInTheDocument();
  });

  it('keeps the table toggle and one source line opening how the record was made, and the views in order', async () => {
    answer = { status: 200, body: benchmark() };
    const { container } = open();
    await screen.findByRole('img', { name: word('bench.r7.judgment.barLabel') });
    const zones = Array.from(
      container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'),
    );
    const pressables = zones.flatMap((zone) =>
      Array.from(zone.querySelectorAll('button, a[href], select, summary')),
    );
    // The bar's table behind "show as a table" and the source line; the drawing counts as one figure.
    expect(pressables.map((element) => element.textContent)).toEqual([
      word('bench.chart.table'),
      word('frame.source.open'),
    ]);
    expect(
      screen.getByText(`${word('frame.space.benchmark')} · ${word('bench.r7.view.judgment')}`),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('frame.back') })).toHaveAttribute(
      'href',
      '/benchmark/cases',
    );
    expect(screen.getByRole('link', { name: word('bench.r7.next.reasoning') })).toHaveAttribute(
      'href',
      '/benchmark/reasoning',
    );
    await userEvent.click(screen.getByRole('button', { name: word('frame.source.open') }));
    expect(screen.getByTestId('where')).toHaveTextContent('modal=method');
    const dialog = screen.getByRole('dialog');
    // What one judgment costs moved here from the old operations tab.
    expect(within(dialog).getByText(fill('detail.seconds', { s: '5.9' }))).toBeInTheDocument();
    expect(dialog).toHaveTextContent('$0.01');
  });
});
