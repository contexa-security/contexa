import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { benchCase, benchmark, stubFetch } from './benchFixture';
import BenchCasesPage from './BenchCasesPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

/** The situations' definitions (/api/cases) the window reads; the words are this test's own. */
const CATALOG = {
  canonicalForm: '',
  rules: { sha256: null, covers: [] },
  classifications: {},
  cases: [
    {
      key: 'T1',
      version: 1,
      title: { ko: 'T1', en: 'T1' },
      protagonist: 'adm-a',
      classification: 'THREAT',
      steps: 1,
      frozenOn: null,
      sha256: '',
      allowedActions: ['BLOCK', 'ESCALATE'],
      rationale: { ko: '이 상황은 막아야 하는 이유가 있습니다.', en: 'A reason to stop it.' },
      counterpoint: { ko: '', en: '' },
    },
  ],
};

let answer: { readonly status: number; readonly body: unknown };

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(stubFetch(() => ({ '/api/benchmark': answer, '/api/cases': { status: 200, body: CATALOG } }))),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
}

function open(path = '/benchmark/cases') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={<BenchCasesPage />} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The B-3 map (docs/showcase/벤치마크-구현계획.md): every situation on one map, grouped by suite and kind. */
describe('benchmark situations', () => {
  it("puts every situation on one map, the named suite first and then each kind, under the server's counts", async () => {
    const runs = { 'run-t1-1': { A: 'MISSED', B: 'MISSED', C1: 'STOPPED', C2: 'STOPPED', D: 'STOPPED' } };
    const base = benchmark({ contexaWrongCases: { THREAT: 2, NORMAL: 1, UNCERTAIN: 0 } });
    answer = {
      status: 200,
      body: {
        ...base,
        suites: base.suites.map((suite) => ({ ...suite, cases: ['T1', 'N1'] })),
        cases: base.cases.map((row) => (row.key === 'T1' ? { ...row, runResults: runs } : row)),
      },
    };
    const { container } = open();
    await screen.findByRole('table', { name: word('bench.chart.map.suite.RULE_BLIND') });
    expect(container.querySelector('main')).toHaveAttribute('data-type', 'table');
    expect(screen.getAllByRole('table').map((table) => table.getAttribute('aria-label'))).toEqual([
      word('bench.chart.map.suite.RULE_BLIND'),
      word('bench.chart.map.kind.THREAT'),
      word('bench.chart.map.kind.NORMAL'),
      word('bench.chart.map.kind.UNCERTAIN'),
    ]);
    // V-11 of docs/showcase/영상전-검토.md: the open situations are counted too, so the kinds add up to the total.
    expect(
      screen.getByText(
        fill('bench.chart.map.counts', {
          attacks: 11,
          attacksWrong: 2,
          normals: 8,
          normalsWrong: 1,
          open: 2,
        }),
      ),
    ).toBeInTheDocument();
    // B-01: the map's legend draws each result as its cell, the open situations' cell included.
    const legend = screen.getByRole('list', { name: word('bench.chart.cellLegend') });
    expect(Array.from(legend.querySelectorAll('li'), (item) => item.getAttribute('data-result'))).toEqual([
      'STOPPED',
      'PARTLY_STOPPED',
      'MISSED',
      'PASSED',
      'PASSED_AFTER_CHECK',
      'HALTED',
      'NOT_SCORED',
    ]);
    expect(legend.querySelector('li[data-result="NOT_SCORED"]')).toHaveTextContent(
      word('bench.chart.cell.NOT_SCORED'),
    );
    expect(
      new Set(
        Array.from(legend.querySelectorAll('[data-tone]:not(li)'), (cell) => cell.getAttribute('data-tone')),
      ).size,
    ).toBe(7);
    const t1 = required(container.querySelector('[role="row"][data-case="T1"]'), 'the T1 row');
    expect([...t1.querySelectorAll('[data-run]')].map((cell) => cell.getAttribute('data-result'))).toEqual([
      'MISSED',
      'MISSED',
      'STOPPED',
      'STOPPED',
      'STOPPED',
    ]);
  });

  it('names a situation in the plain words of the dictionary where it has them', async () => {
    answer = {
      status: 200,
      body: benchmark({
        cases: [benchCase('A3', 'THREAT', { D: [5, 5] }), benchCase('S08', 'UNCERTAIN', {})],
        caseCounts: { THREAT: 1, NORMAL: 0, UNCERTAIN: 1 },
      }),
    };
    open();
    expect(await screen.findByRole('button', { name: word('bench.r7.caseName.A3') })).toBeInTheDocument();
  });

  it("keeps the filter, 'see details' and the source line's record as the things to press, the map counting as one figure", async () => {
    answer = { status: 200, body: benchmark() };
    const { container } = open();
    await screen.findAllByRole('table');
    const zones = Array.from(
      container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'),
    );
    const pressables = zones.flatMap((zone) =>
      Array.from(zone.querySelectorAll('button, a[href], select, summary, input')).filter(
        (element) => element.closest('[data-count="exempt"]') === null,
      ),
    );
    expect(pressables).toHaveLength(3);
    const source = required(container.querySelector<HTMLElement>('[data-zone="source"]'), 'the source line');
    expect(source).toHaveTextContent(word('frame.source.measured'));
    // L-40 of docs/showcase/영상전-검토.md: the source line opens how the record was made, as on the other views.
    await userEvent.click(within(source).getByRole('button', { name: word('frame.source.open') }));
    expect(screen.getByTestId('where')).toHaveTextContent('modal=method');
    expect(screen.getByText(word('bench.r7.footnote'))).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('frame.back') })).toHaveAttribute(
      'href',
      '/benchmark/approaches',
    );
    expect(screen.getByRole('link', { name: word('bench.r7.next.judgment') })).toHaveAttribute(
      'href',
      '/benchmark/judgment',
    );
  });

  it("opens the server's first situation in its window, where another can be chosen", async () => {
    answer = { status: 200, body: benchmark() };
    open();
    // L-42: the view's one "see details" chip has the name every benchmark view gives it.
    await userEvent.click(await screen.findByRole('button', { name: word('frame.detail') }));
    expect(screen.getByTestId('where')).toHaveTextContent('modal=case&case=N1');
    expect(screen.getByRole('dialog')).toHaveTextContent(word('bench.r7.case.answer.pass'));
    await userEvent.selectOptions(
      within(screen.getByRole('dialog')).getByRole('combobox', { name: word('bench.r7.case.choose') }),
      'T1',
    );
    expect(screen.getByTestId('where')).toHaveTextContent('case=T1');
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent(word('bench.r7.case.answer.stop'));
    expect(await within(dialog).findByText('이 상황은 막아야 하는 이유가 있습니다.')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(fill('bench.r7.case.runs', { n: 5 }));
    // V-48 of docs/showcase/영상전-검토.md: the run's button says what it opens; the run ID stays small, as the original.
    expect(
      within(dialog).getByRole('button', { name: fill('bench.r7.case.openRun', { n: 1 }) }),
    ).toBeInTheDocument();
    expect(within(dialog).getByText('run-t1aaaaaa1')).toHaveAttribute('data-original');
    // B-20: the expected handling in neutral chips (never a verdict's colour beside the table's), why holding counts,
    // and the cells named.
    expect(dialog).toHaveTextContent(word('bench.r7.case.allowed'));
    expect(dialog.querySelector('[data-verdict]')).toBeNull();
    expect(Array.from(dialog.querySelectorAll('[data-allowed]'), (chip) => chip.textContent)).toEqual([
      word('verdict.block'),
      word('verdict.review'),
    ]);
    expect(dialog).toHaveTextContent(word('bench.r7.case.held'));
    expect(dialog).toHaveTextContent(
      fill('bench.r7.case.cell', { score: word('bench.r7.score.stoppedAny'), right: 5, counted: 5 }),
    );
  });
});
