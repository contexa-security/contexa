import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import BenchApproachesPage from './BenchApproachesPage';
import { benchmark, stubFetch } from './benchFixture';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/[{][{](\w+)[}][}]/g, (_, name: string) => String(values[name] ?? ''));
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

function open(path = '/benchmark/approaches') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={<BenchApproachesPage />} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** B-2 of docs/showcase/벤치마크-구현계획.md: the approaches on one chart, then the three questions the server answers. */
describe('benchmark approaches', () => {
  it('places the five approaches on the chart and answers the three questions with the server picks', async () => {
    answer = { status: 200, body: benchmark() };
    const { container } = open();
    expect(
      await screen.findByRole('img', { name: word('bench.chart.approaches.summary') }),
    ).toBeInTheDocument();
    expect(container.querySelectorAll('svg [data-point]')).toHaveLength(5);
    expect(container.querySelector('main')).toHaveAttribute('data-type', 'table');
    const questions = screen.getByRole('list', { name: word('bench.r7.summary.questions') });
    expect(within(questions).getAllByRole('listitem')).toHaveLength(3);
    // V-22 of docs/showcase/영상전-검토.md: the third question asks what the server picks.
    expect(within(questions).getAllByRole('listitem')[2]).toHaveTextContent(
      word('benchmark.question.cleanMostStopped'),
    );
    // L-39 of docs/showcase/영상전-검토.md: the third card's value is the count only (its question already says no
    // normal work was blocked), so it is no longer the one card whose value breaks into two lines.
    expect(within(questions).getAllByRole('listitem')[2]).toHaveTextContent(
      fill('benchmark.answerValue.cleanMostStopped', { hits: 85, total: 85 }),
    );
    expect(word('benchmark.answerValue.cleanMostStopped')).toBe(word('benchmark.answerValue.mostStopped'));
    // L-39: under the chart, what the crosses are (the 95% interval) and the runs counted, Contexa's totals as sent.
    expect(
      required(container.querySelector('[data-chart-note]'), 'the note under the chart'),
    ).toHaveTextContent(
      `${word('bench.chart.approaches.cross')} ${fill('bench.chart.approaches.basis', { attacks: 85, normals: 75 })}`,
    );
    // V-23: Contexa's count holds the attacks the sign-in check refused first, before the AI judged.
    expect(
      screen.getByText(fill('bench.r7.approaches.staticNote', { hits: 85, total: 85, count: 5 })),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('frame.back') })).toHaveAttribute('href', '/benchmark');
    expect(screen.getByRole('link', { name: word('bench.r7.next.cases') })).toHaveAttribute(
      'href',
      '/benchmark/cases',
    );
  });

  it('shows a named suite in the address with its own picks', async () => {
    answer = { status: 200, body: benchmark() };
    open();
    await userEvent.selectOptions(
      await screen.findByRole('combobox', { name: word('bench.r7.summary.suite') }),
      'RULE_BLIND',
    );
    expect(screen.getByTestId('where')).toHaveTextContent('/benchmark/approaches?suite=RULE_BLIND');
    const first = required(
      screen.getByRole('list', { name: word('bench.r7.summary.questions') }).querySelector('li'),
      'the first question',
    );
    // The fixture's suite names the approval rule and Contexa together for the first question (a tie).
    expect(first).toHaveTextContent(`${word('control.C2.name')} * · ${word('control.D.name')}`);
    // The refusals are counted over every situation, so a named group does not state them.
    expect(
      screen.queryByText(fill('bench.r7.approaches.staticNote', { hits: 85, total: 85, count: 5 })),
    ).toBeNull();
  });
});
