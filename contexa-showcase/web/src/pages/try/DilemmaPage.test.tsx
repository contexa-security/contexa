import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import DilemmaPage from './DilemmaPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

interface Score {
  readonly falseBlock?: number;
  readonly stopped?: number;
  readonly missed?: number;
}

function control(id: string, score: Score) {
  return {
    control: id,
    falseBlock: { hits: score.falseBlock ?? 0, total: 75 },
    stopped: { hits: score.stopped ?? 0, total: 85 },
    missed: score.missed ?? 0,
  };
}

interface Measured {
  readonly c1: Score;
  readonly c2: Score;
  readonly d: Score;
  readonly blindC2: Score;
  readonly blindD: Score;
  readonly judged: { readonly runs: number; readonly stopped: number };
}

/** The parts of the portal's benchmark view the screen reads (BenchmarkView); the numbers are this test's own. */
function benchmark(measured: Measured) {
  return {
    controls: [control('C1', measured.c1), control('C2', measured.c2), control('D', measured.d)],
    suites: [
      { suite: 'RULE_BLIND', controls: [control('C2', measured.blindC2), control('D', measured.blindD)] },
    ],
    riskJudged: measured.judged,
    scope: { runs: 170, cases: 34 },
    spec: null,
  };
}

/** Two measurements with different values, so a column that shows a constant fails one of them. */
const RECORDS = [
  {
    name: 'every risky attack stopped, no normal work stopped',
    measured: {
      c1: { falseBlock: 40, missed: 25 },
      c2: { stopped: 60 },
      d: { falseBlock: 0 },
      blindC2: { missed: 20 },
      blindD: {},
      judged: { runs: 80, stopped: 80 },
    },
    columns: { C1: ['40', '25'], C2: ['60', '20'], D: ['0', '80'] },
    judgedLabel: word('p5.dilemma.judgedAll'),
    sentence: word('p5.dilemma.sentence.clean'),
  },
  {
    name: 'normal work stopped and some risky attacks through',
    measured: {
      c1: { falseBlock: 1234, missed: 3 },
      c2: { stopped: 7 },
      d: { falseBlock: 2, missed: 4 },
      blindC2: { missed: 0 },
      blindD: { missed: 1 },
      judged: { runs: 50, stopped: 46 },
    },
    columns: { C1: ['1,234', '3'], C2: ['7', '0'], D: ['2', '46'] },
    judgedLabel: fill('p5.dilemma.judgedSome', { runs: '50' }),
    sentence: word('p5.dilemma.sentence.both'),
  },
] as const;

let answer: { readonly status: number; readonly body: unknown };

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
            state: { route: 'DEFAULT', act: 5, step: 'dilemma', differences: [] },
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
      <MemoryRouter initialEntries={['/try/summary/dilemma']}>
        <DilemmaPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function numbers(name: string): readonly string[] {
  const column = screen.getByRole('region', { name });
  return Array.from(column.querySelectorAll('dd'), (value) => value.textContent ?? '');
}

/** Screen 5-1 (화면재편-기획안 7절, T5): one sentence the counts pick, three columns of two numbers each. */
// The final screen design (최종화면-구현계획 F0-1) opens this screen at no address any more; its address leads to the
// new flow. The screen and this test are on the deletion list for the user (최종화면-구현계획 4절).
describe.skip('the numbers on the same situations', () => {
  it.each(RECORDS)('shows the benchmark counts in the three columns as recorded ($name)', async (record) => {
    answer = { status: 200, body: benchmark(record.measured) };
    open();
    await screen.findByRole('region', { name: word('control.D.name') });
    expect(numbers(word('control.C1.name'))).toEqual(record.columns.C1);
    // The approval and owner check carries the note mark: a rule written after looking at these situations.
    expect(numbers(`${word('control.C2.name')}*`)).toEqual(record.columns.C2);
    expect(screen.getByText(word('p5.dilemma.note'))).toBeInTheDocument();
    expect(numbers(word('control.D.name'))).toEqual(record.columns.D);
    const contexa = screen.getByRole('region', { name: word('control.D.name') });
    expect(within(contexa).getByText(record.judgedLabel)).toBeInTheDocument();
    expect(screen.getByText(record.sentence)).toBeInTheDocument();
  });

  it('adds that some attacks got through when Contexa missed any, even with every risky one stopped', async () => {
    answer = {
      status: 200,
      body: benchmark({ ...RECORDS[0].measured, blindD: { missed: 3 } }),
    };
    open();
    expect(
      await screen.findByText(`${word('p5.dilemma.sentence.clean')} ${word('p5.dilemma.missed')}`),
    ).toBeInTheDocument();
  });

  it('says Contexa judged no attack risky when the record has none, never that it stopped them all', async () => {
    answer = { status: 200, body: benchmark({ ...RECORDS[0].measured, judged: { runs: 0, stopped: 0 } }) };
    open();
    expect(await screen.findByText(word('p5.dilemma.sentence.noJudgedClean'))).toBeInTheDocument();
    expect(screen.queryByText(word('p5.dilemma.sentence.clean'))).not.toBeInTheDocument();
    const contexa = screen.getByRole('region', { name: word('control.D.name') });
    expect(within(contexa).getByText(fill('p5.dilemma.judgedSome', { runs: '0' }))).toBeInTheDocument();
    expect(within(contexa).queryByText(word('p5.dilemma.judgedAll'))).not.toBeInTheDocument();
  });

  it('keeps one source line and nothing to press in the body', async () => {
    answer = { status: 200, body: benchmark(RECORDS[0].measured) };
    const { container } = open();
    await screen.findByRole('region', { name: word('control.D.name') });
    const source = required(container.querySelector<HTMLElement>('[data-zone="source"]'), 'the source line');
    expect(source).toHaveTextContent(word('frame.source.measured'));
    const zones = Array.from(
      container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'),
    );
    expect(zones.flatMap((zone) => Array.from(zone.querySelectorAll('button, a[href]')))).toHaveLength(0);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.5-1.title'));
    expect(screen.getByRole('link', { name: word('screen.5-1.next') })).toHaveAttribute(
      'href',
      '/try/summary/recap',
    );
    // Gone: the old conclusion band, the notes and the lab chip.
    const text = document.body.textContent ?? '';
    for (const key of ['dilemma.conclusion', 'dilemma.tighten', 'hook.note', 'dilemma.meaning.C2']) {
      expect(text, key).not.toContain(word(key));
    }
  });

  it('says the record is being prepared when there is no benchmark, with no numbers and no source line', async () => {
    answer = { status: 404, body: null };
    const { container } = open();
    expect(await screen.findByText(word('state.notReady'))).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: word('control.D.name') })).not.toBeInTheDocument();
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
  });
});
