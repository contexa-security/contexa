import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { benchCase, benchmark, score, stubFetch } from './benchFixture';
import BenchLimitsPage from './BenchLimitsPage';
import charts from './charts/Charts.module.css';

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
      <MemoryRouter initialEntries={['/benchmark/limits']}>
        <Routes>
          <Route path="*" element={<BenchLimitsPage />} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function pressables(container: HTMLElement): readonly Element[] {
  return Array.from(
    container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'),
  ).flatMap((zone) =>
    // As the automatic check counts them (e2e/frameMeasure.mjs): a chart's drawing counts as one figure.
    Array.from(zone.querySelectorAll('button, a[href], select, summary')).filter(
      (element) => element.closest('[data-count="exempt"]') === null,
    ),
  );
}

/** One attack Contexa let through every time it was sent, one normal task it blocked once, as the portal flags them. */
function missedOnce() {
  const missed = benchCase(
    'S06',
    'THREAT',
    { D: [0, 5] },
    {
      missedEveryRun: true,
      contexaWrong: true,
      runResults: { 'run-s06-1': { D: 'MISSED' }, 'run-s06-2': { D: 'MISSED' } },
    },
  );
  const halted = benchCase(
    'N1',
    'NORMAL',
    { D: [4, 5] },
    {
      contexaWrong: true,
      runResults: { 'run-n1-1': { D: 'HALTED' }, 'run-n1-2': { D: 'PASSED' } },
    },
  );
  return benchmark({
    cases: [benchCase('T1', 'THREAT', { D: [5, 5] }), missed, halted],
    wrongRuns: [
      {
        runId: 'run-s06-2',
        caseKey: 'S06',
        classification: 'THREAT',
        result: 'MISSED',
        exposedItems: 3,
        stepNo: 1,
        finalAction: 'ALLOW',
        riskScore: 0.2,
        reasoning: 'Assigned work within the usual pattern.',
        coreAdverseMet: null,
        startedAt: '2026-10-17T09:00:00Z',
      },
    ],
    missedEveryRunCases: ['S06'],
    controls: [score('D', { stopped: [12, 40], stoppedAny: [35, 40], notBlocked: [30, 30], exposed: 7 })],
  });
}

/** The limits (화면재편-구현계획 RO-3, every RC-1 limit): what Contexa missed and why, as the server counted it. */
describe('benchmark limits', () => {
  it("says no attack was missed every time when the server names none, with Contexa's three numbers", async () => {
    answer = { status: 200, body: benchmark() };
    const { container } = open();
    expect(await screen.findByText(word('bench.r7.limits.missedNone'))).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('bench.r7.limits.title'));
    expect(container.querySelector('main')).toHaveAttribute('data-type', 'T6');
    const figures = required(container.querySelector('dl'), 'the three numbers');
    expect(Array.from(figures.querySelectorAll('dd'), (value) => value.textContent)).toEqual([
      '30/85',
      '85/85',
      fill('bench.r7.items', { items: '50,755' }),
    ]);
    expect(screen.getByText(fill('bench.r7.limits.why', { timing: 10, judged: 3 }))).toBeInTheDocument();
    // V-23 of docs/showcase/영상전-검토.md: both counts hold the attacks the sign-in check refused before the AI judged.
    expect(screen.getByText(fill('bench.r7.limits.staticNote', { count: 5 }))).toBeInTheDocument();
    // V-24: the items that left, before and after a decision, as leaked items; T-11: the deck's name of the timing.
    expect(screen.getByText(word('bench.r7.limits.exposed'))).toBeInTheDocument();
    // L-41: the line that says nothing was got wrong is written in the body colour, as the labels under the numbers.
    expect(screen.getByText(word('bench.chart.limits.none.NORMAL'))).toHaveClass(
      required(charts.noneLine, 'the class of the empty line'),
    );
    expect(word('bench.chart.limits.explain.async')).toContain('다음 요청부터 차단(비동기 판단)');
    // Nothing missed: nothing to open; only the source line's button and no link in the body.
    expect(pressables(container).map((element) => element.textContent)).toEqual([word('frame.source.open')]);
    expect(screen.getByRole('link', { name: word('frame.back') })).toHaveAttribute(
      'href',
      '/benchmark/reasoning',
    );
    expect(screen.getByRole('link', { name: word('bench.r7.next.lab') })).toHaveAttribute('href', '/lab');
  });

  it("names the attacks missed every time and opens the first in the situations' window", async () => {
    answer = { status: 200, body: missedOnce() };
    const { container } = open();
    // V-25: the attacks let through every time they were sent, without the range of sends of every case.
    expect(await screen.findByText(fill('bench.r7.limits.missed', { count: 1 }))).toBeInTheDocument();
    expect(screen.getByText(word('bench.r7.caseName.S06'))).toBeInTheDocument();
    // The attacks Contexa let through and the normal work it blocked, as the server flagged them, each with its
    // cells and the reason the model wrote in its newest wrong run, kept as the original.
    const missedGroup = screen.getByRole('region', { name: word('bench.chart.limits.missedTitle') });
    expect(missedGroup.querySelectorAll('[data-run]')).toHaveLength(2);
    expect(within(missedGroup).getByText('Assigned work within the usual pattern.')).toHaveAttribute(
      'data-original',
    );
    const haltedGroup = screen.getByRole('region', { name: word('bench.chart.limits.haltedTitle') });
    expect(haltedGroup.querySelector('[data-result="HALTED"]')).not.toBeNull();
    const figures = required(container.querySelector('dl'), 'the three numbers');
    expect(within(figures).getByText('12/40')).toBeInTheDocument();
    expect(within(figures).getByText(fill('bench.r7.items', { items: '7' }))).toBeInTheDocument();
    expect(pressables(container)).toHaveLength(2);
    await userEvent.click(screen.getByRole('button', { name: word('frame.detail') }));
    expect(screen.getByTestId('where')).toHaveTextContent('modal=case&case=S06');
  });

  // L-41 of docs/showcase/영상전-검토.md: a missed attack's card says what leaked in the run its reason comes from, as
  // the server counted it, and opens that run's record; normal work with no wrong run listed has no run to open.
  it("says what leaked in a missed attack's run and opens that run's record", async () => {
    answer = { status: 200, body: missedOnce() };
    open();
    const missedGroup = await screen.findByRole('region', { name: word('bench.chart.limits.missedTitle') });
    expect(
      within(missedGroup).getByText(fill('bench.chart.limits.leaked', { items: '3' })),
    ).toBeInTheDocument();
    await userEvent.click(
      within(missedGroup).getByRole('button', { name: word('bench.chart.limits.openRun') }),
    );
    expect(screen.getByTestId('where')).toHaveTextContent('modal=detail&detailRun=run-s06-2');
    const haltedGroup = screen.getByRole('region', { name: word('bench.chart.limits.haltedTitle') });
    expect(
      within(haltedGroup).queryByRole('button', { name: word('bench.chart.limits.openRun') }),
    ).toBeNull();
  });

  // V-01: the reason line names the "other" runs as the portal sent them, each with its result, so it adds up.
  it("names the 'other' runs in the reason line with their results", async () => {
    const base = benchmark({
      cases: [benchCase('S11', 'THREAT', {}), benchCase('S19', 'THREAT', {})],
      judgmentTiming: { STATIC_REFUSAL: 1, BEFORE_RESPONSE: 6, NEXT_REQUEST: 13, JUDGED_ALLOW: 1, OTHER: 2 },
    });
    answer = {
      status: 200,
      body: {
        ...base,
        judgmentOthers: [
          { runId: 'run-s11', caseKey: 'S11', result: 'PARTLY_STOPPED', exposedItems: 480, steps: [] },
          { runId: 'run-s19', caseKey: 'S19', result: 'MISSED', exposedItems: 3, steps: [] },
        ],
      },
    };
    open();
    expect(
      await screen.findByText(fill('bench.r7.limits.why', { timing: 13, judged: 1 })),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        fill('bench.r7.limits.whyOthers', {
          n: 2,
          runs: [
            fill('bench.r7.limits.whyOther', {
              name: word('bench.r7.caseName.S11'),
              result: word('main.result.PARTLY_STOPPED'),
            }),
            fill('bench.r7.limits.whyOther', {
              name: word('bench.r7.caseName.S19'),
              result: word('main.result.MISSED'),
            }),
          ].join(' · '),
        }),
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(fill('bench.r7.limits.staticNote', { count: 1 }))).toBeInTheDocument();
  });
});
