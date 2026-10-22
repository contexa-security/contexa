import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';
import type { BenchmarkCase, BenchmarkView } from '../../../api/benchmark';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { CaseMap } from './CaseMap';

const KO: Readonly<Record<string, string>> = ko;
const word = (key: string): string => KO[key] ?? key;

const all = (result: string, contexa: string) => ({
  A: result,
  B: result,
  C1: result,
  C2: result,
  D: contexa,
});

function row(
  key: string,
  classification: string,
  runResults: Record<string, Record<string, string>>,
  wrong = false,
) {
  return {
    key,
    classification,
    title: { ko: key, en: key },
    runResults,
    contexaWrong: wrong,
  } as unknown as BenchmarkCase;
}

/** Cases as the portal sends them: two in the rule-blind suite, one attack and one normal task outside it. */
const VIEW = {
  suites: [{ suite: 'RULE_BLIND', cases: ['S17', 'S17T'] }],
  caseCounts: { THREAT: 2, NORMAL: 2, UNCERTAIN: 0 },
  cases: [
    row('A3', 'THREAT', { 'run-1': all('STOPPED', 'STOPPED') }),
    row('S17', 'THREAT', { 'run-2': all('MISSED', 'MISSED'), 'run-3': all('MISSED', 'STOPPED') }, true),
    row('S17T', 'NORMAL', { 'run-4': all('PASSED', 'HALTED') }, true),
    row('A3T', 'NORMAL', { 'run-5': all('HALTED', 'PASSED') }),
  ],
} as unknown as BenchmarkView;

function Where() {
  return <output data-testid="where">{useLocation().search}</output>;
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

function open() {
  return render(
    <MemoryRouter initialEntries={['/benchmark/cases']}>
      <CaseMap view={VIEW} nameOf={(found) => `name-${found.key}`} />
      <Where />
    </MemoryRouter>,
  );
}

describe('the case map', () => {
  it('groups the situations by the named suite first, then by kind, a cell per run for each approach', () => {
    open();
    const groups = screen.getAllByRole('table').map((table) => table.getAttribute('aria-label'));
    expect(groups).toEqual([
      word('bench.chart.map.suite.RULE_BLIND'),
      word('bench.chart.map.kind.THREAT'),
      word('bench.chart.map.kind.NORMAL'),
    ]);
    const s17 = screen.getAllByRole('row').find((found) => found.dataset.case === 'S17') as HTMLElement;
    const cells = within(s17).getAllByRole('cell');
    expect(cells).toHaveLength(5);
    expect(
      [...(cells.at(4)?.querySelectorAll('[data-run]') ?? [])].map((cell) =>
        cell.getAttribute('data-result'),
      ),
    ).toEqual(['MISSED', 'STOPPED']);
    expect(within(s17).getByText(word('bench.chart.map.answer.THREAT'))).toBeInTheDocument();
  });

  it("opens a situation's window from its name and keeps only the situations Contexa got wrong when asked", () => {
    const { container } = open();
    fireEvent.click(screen.getByRole('button', { name: 'name-A3T' }));
    expect(screen.getByTestId('where').textContent).toContain('case=A3T');
    fireEvent.click(screen.getByLabelText(word('bench.chart.map.wrongOnly')));
    expect(
      [...container.querySelectorAll('[role="row"][data-case]')].map((found) =>
        found.getAttribute('data-case'),
      ),
    ).toEqual(['S17', 'S17T']);
  });
});
