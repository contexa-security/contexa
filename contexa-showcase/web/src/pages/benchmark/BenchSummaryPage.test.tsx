import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { BlindSpot } from '../../api/benchmark';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { benchmark, stubFetch } from './benchFixture';
import BenchSummaryPage from './BenchSummaryPage';

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

function open(path = '/benchmark') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={<BenchSummaryPage />} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The proof as a portal with BM-S2 sends it: one designed pair, a miss on the attack side and a halt on the other. */
const PROOF: BlindSpot = {
  attacks: [
    {
      key: 'T1',
      runs: 3,
      allPassed: 3,
      contexa: { STOPPED: 2, MISSED: 1 },
      passedRuns: [
        { runId: 'run-a1', result: 'STOPPED' },
        { runId: 'run-a2', result: 'MISSED' },
        { runId: 'run-a3', result: 'STOPPED' },
      ],
    },
  ],
  normals: [
    {
      key: 'N1',
      runs: 3,
      allPassed: 3,
      contexa: { PASSED: 2, HALTED: 1 },
      passedRuns: [
        { runId: 'run-n1', result: 'PASSED' },
        { runId: 'run-n2', result: 'PASSED' },
        { runId: 'run-n3', result: 'HALTED' },
      ],
    },
  ],
  pairs: [{ group: 'STOLEN_ACCOUNT', attack: 'T1', normal: 'N1' }],
  totals: {
    attackRuns: 3,
    attackAllPassed: 3,
    contexaStopped: 2,
    contexaFullyStopped: 2,
    normalRuns: 3,
    normalAllPassed: 3,
    contexaPassed: 2,
  },
};

/** B-1 of docs/showcase/벤치마크-구현계획.md: the proof first, the portal's counts as they came, misses included. */
describe('benchmark summary', () => {
  // BM-S9: a measurement stopped before its plan states the runs per case as measured, not the planned repeat.
  it('says how many times each case was sent as measured', async () => {
    const view = benchmark({ blindSpot: PROOF });
    answer = {
      status: 200,
      body: { ...view, scope: { ...view.scope, fewestRunsPerCase: 1, mostRunsPerCase: 2 } },
    };
    open();
    expect(
      await screen.findByText(
        fill('bench.r7.summary.scope', {
          cases: 21,
          attacks: 11,
          normals: 8,
          open: 2,
          repeat: '1~2',
          runs: 105,
        }),
      ),
    ).toBeInTheDocument();
  });

  // V-11, V-26 and V-64 of docs/showcase/영상전-검토.md: the situations by kind add up to their count, the decisions
  // are told apart from the runs, and the pairs say why only they are shown and that two share their normal work.
  it('splits the situations by kind, tells decisions from runs and marks the normal work two pairs share', async () => {
    const shared = {
      ...PROOF,
      attacks: [...PROOF.attacks, { ...(PROOF.attacks[0] as BlindSpot['attacks'][number]), key: 'T2' }],
      pairs: [
        { group: 'INSIDER', attack: 'T1', normal: 'N1' },
        { group: 'INSIDER', attack: 'T2', normal: 'N1' },
      ],
      sharedNormals: ['N1'],
    };
    answer = { status: 200, body: benchmark({ blindSpot: shared }) };
    const { container } = open();
    expect(
      await screen.findByText(
        fill('bench.r7.summary.scope', { cases: 21, attacks: 11, normals: 8, open: 2, repeat: 5, runs: 105 }),
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(fill('bench.r7.summary.decisions', { decisions: 120 }))).toBeInTheDocument();
    expect(screen.getByText(fill('bench.r7.summary.pairs', { count: 2 }))).toBeInTheDocument();
    const normals = Array.from(container.querySelectorAll('[data-side="normal"][data-case="N1"]'));
    expect(normals).toHaveLength(2);
    for (const normal of normals) {
      expect(normal).toHaveTextContent(word('bench.chart.pair.shared'));
    }
  });

  it('states the five criteria with the counts and draws each pair, a cell per run, misses included', async () => {
    answer = { status: 200, body: benchmark({ blindSpot: PROOF }) };
    const { container } = open();
    const lines = await screen.findByRole('list', { name: word('bench.chart.proof.title') });
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('bench.chart.summary.title'));
    expect(
      screen.getByText(
        fill('bench.r7.summary.scope', { cases: 21, attacks: 11, normals: 8, open: 2, repeat: 5, runs: 105 }),
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(word('bench.chart.pair.shared'))).toBeNull();
    expect(within(lines).getAllByRole('listitem')[0]).toHaveTextContent(
      fill('bench.chart.proof.ofRuns', { n: 3, of: 3 }),
    );
    expect(within(lines).getAllByRole('listitem')[2]).toHaveTextContent(
      fill('bench.chart.proof.g3Value', { stopped: 2, fully: 2, attacks: 3, passed: 2, normals: 3 }),
    );
    const attack = required(container.querySelector<HTMLElement>('[data-case="T1"]'), 'the attack line');
    expect(
      [...attack.querySelectorAll('[data-run]')].map((cell) => cell.getAttribute('data-result')),
    ).toEqual(['STOPPED', 'MISSED', 'STOPPED']);
    expect(container.querySelector('[data-result="HALTED"][data-run]')).not.toBeNull();
    expect(container.querySelector('li[data-result="MISSED"]')).toHaveTextContent(word('main.result.MISSED'));
  });

  it('shows the proof tables from a portal without the pairs', async () => {
    answer = {
      status: 200,
      body: benchmark({ blindSpot: { attacks: PROOF.attacks, normals: PROOF.normals } }),
    };
    open();
    expect(await screen.findByRole('region', { name: word('bench.r7.proof.attacks') })).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: word('bench.chart.proof.title') })).toBeNull();
  });

  it("keeps 'see details' as the body's one thing to press, one source line, and the approaches next", async () => {
    answer = { status: 200, body: benchmark({ blindSpot: PROOF }) };
    const { container } = open();
    await screen.findByRole('list', { name: word('bench.chart.proof.title') });
    const pressables = Array.from(
      container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'),
    ).flatMap((zone) =>
      Array.from(zone.querySelectorAll('button, a[href], select, input, summary')).filter(
        (element) => element.closest('[data-count="exempt"]') === null,
      ),
    );
    expect(pressables.map((element) => element.textContent)).toEqual([
      word('frame.detail'),
      word('frame.source.open'),
    ]);
    expect(
      screen.getByText(`${word('frame.space.benchmark')} · ${word('bench.r7.view.summary')}`),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('bench.r7.next.approaches') })).toHaveAttribute(
      'href',
      '/benchmark/approaches',
    );
  });
});
