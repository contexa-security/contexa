import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';
import type { BlindSpot } from '../../../api/benchmark';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { PairBars } from './PairBars';

const KO: Readonly<Record<string, string>> = ko;
const word = (key: string): string => KO[key] ?? key;

/** The proof as the portal sends it: a pair with a miss, a pair whose normal side was once halted, an attack alone. */
const PROOF: BlindSpot = {
  attacks: [
    {
      key: 'S17',
      runs: 5,
      allPassed: 5,
      contexa: { STOPPED: 1, MISSED: 4 },
      passedRuns: [
        { runId: 'run-a1', result: 'MISSED' },
        { runId: 'run-a2', result: 'STOPPED' },
        { runId: 'run-a3', result: 'MISSED' },
        { runId: 'run-a4', result: 'MISSED' },
        { runId: 'run-a5', result: 'MISSED' },
      ],
    },
    { key: 'K2', runs: 5, allPassed: 5, contexa: { MISSED: 5 } },
  ],
  normals: [
    {
      key: 'S17T',
      runs: 5,
      allPassed: 5,
      contexa: { HALTED: 1, PASSED: 4 },
      passedRuns: [
        { runId: 'run-n1', result: 'PASSED' },
        { runId: 'run-n2', result: 'HALTED' },
        { runId: 'run-n3', result: 'PASSED' },
        { runId: 'run-n4', result: 'PASSED' },
        { runId: 'run-n5', result: 'PASSED' },
      ],
    },
  ],
  pairs: [{ group: 'STOLEN_ACCOUNT', attack: 'S17', normal: 'S17T' }],
};

function Where() {
  const location = useLocation();
  return <output data-testid="where">{location.search}</output>;
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

function open() {
  return render(
    <MemoryRouter initialEntries={['/benchmark']}>
      <PairBars proof={PROOF} nameOf={(key) => `name-${key}`} />
      <Where />
    </MemoryRouter>,
  );
}

describe('the blind-spot pairs', () => {
  it("puts each attack over its normal pair with a cell per counted run and Contexa's counts, misses included", () => {
    const { container } = open();
    const group = screen.getByRole('region', { name: word('bench.chart.pair.group.STOLEN_ACCOUNT') });
    const attack = container.querySelector('[data-case="S17"]') as HTMLElement;
    expect(within(group).getByText('name-S17')).toBeInTheDocument();
    expect([...attack.querySelectorAll('[data-run]')].map((cell) => cell.textContent)).toEqual([
      '✕',
      '●',
      '✕',
      '✕',
      '✕',
    ]);
    expect(attack).toHaveTextContent(
      word('bench.r7.proof.allPassedValue').replace('{{passed}}', '5').replace('{{runs}}', '5'),
    );
    expect(attack).toHaveTextContent(`${word('main.result.STOPPED')} 1 · ${word('main.result.MISSED')} 4`);
    const normal = container.querySelector('[data-case="S17T"]') as HTMLElement;
    expect(normal.querySelector('[data-run="run-n2"]')).toHaveAttribute('data-tone', 'halt');
  });

  it('lists an attack without a pair apart, and opens a run’s evidence from its cell', () => {
    open();
    expect(screen.getByRole('region', { name: word('bench.chart.pair.group.alone') })).toHaveTextContent(
      'name-K2',
    );
    fireEvent.click(screen.getByRole('button', { name: `실행 run-a2 · ${word('main.result.STOPPED')}` }));
    expect(screen.getByTestId('where').textContent).toContain('detailRun=run-a2');
  });
});
