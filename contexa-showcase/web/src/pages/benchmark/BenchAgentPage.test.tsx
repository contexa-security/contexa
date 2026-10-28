import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import BenchAgentPage from './BenchAgentPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

const VIEW = {
  scope: { runs: 276, cases: 75, from: '2026-10-23T03:00:00Z', to: '2026-10-26T12:00:00Z' },
  byPath: [
    { path: 'DELEGATED_AGENT', runs: 120, attacks: 90, existingMissed: 50, contexaStopped: 25, normals: 30, falseBlocks: 6, contexaShare: 0.5 },
    { path: 'AUTONOMOUS_AGENT', runs: 100, attacks: 76, existingMissed: 40, contexaStopped: 20, normals: 24, falseBlocks: 5, contexaShare: 0.5 },
    { path: 'AGENT_SESSION', runs: 56, attacks: 40, existingMissed: 28, contexaStopped: 12, normals: 16, falseBlocks: 3, contexaShare: 12 / 28 },
  ],
  total: { path: 'ALL', runs: 276, attacks: 206, existingMissed: 118, contexaStopped: 57, normals: 70, falseBlocks: 14, contexaShare: 57 / 118 },
  variation: { cells: 60, differing: 22 },
  notMeasured: ['M99A', 'M98A'],
  contexaMissed: ['M11A', 'M13A'],
};

let bodies: Record<string, unknown>;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  bodies = { '/api/visitor': { predictions: {} }, '/api/benchmark/agent': VIEW };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body === undefined ? 404 : 200 });
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
      <MemoryRouter initialEntries={['/benchmark/agent']}>
        <Routes>
          <Route path="*" element={<BenchAgentPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('the benchmark of the agent runs (AS-11)', () => {
  it('says in one line how much of what every existing control let through Contexa stopped, as the portal counted it', async () => {
    open();

    expect(
      await screen.findByText(
        word('bench.agent.result').replace('{{missed}}', '118').replace('{{stopped}}', '57').replace('{{percent}}', '48.3%'),
      ),
    ).toBeInTheDocument();
  });

  it('lists each path with its counts and the subject chip of its sender', async () => {
    open();

    const table = await screen.findByRole('table', { name: word('bench.agent.paths') });
    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(1 + 3 + 1);
    expect(within(rows[1] as HTMLElement).getByLabelText('보내는 쪽: 위임 에이전트')).toBeInTheDocument();
    expect(within(rows[2] as HTMLElement).getByLabelText('보내는 쪽: 단독 에이전트')).toBeInTheDocument();
    expect(within(rows[3] as HTMLElement).getByLabelText('보내는 쪽: 세션 에이전트')).toBeInTheDocument();
    expect(rows[1]?.textContent).toContain('120');
    expect(rows[4]?.textContent).toContain('276');
  });

  it("says the normal work Contexa stopped and the cells that ended differently, from the portal's counts", async () => {
    open();

    expect(
      await screen.findByText(word('bench.agent.falseBlocks').replace('{{blocked}}', '14').replace('{{normals}}', '70')),
    ).toBeInTheDocument();
    expect(
      screen.getByText(word('bench.agent.variation').replace('{{differing}}', '22').replace('{{cells}}', '60')),
    ).toBeInTheDocument();
  });

  it('names what was not measured and what Contexa missed, never leaving them out', async () => {
    open();

    expect(await screen.findByText(word('bench.agent.notMeasured').replace('{{n}}', '2'))).toBeInTheDocument();
    expect(screen.getByText('M99A, M98A')).toBeInTheDocument();
    expect(screen.getByText(word('bench.agent.missed').replace('{{n}}', '2'))).toBeInTheDocument();
    expect(screen.getByText('M11A, M13A')).toBeInTheDocument();
  });

  it('shows no figure before the portal has counted any run, and says so', async () => {
    bodies['/api/benchmark/agent'] = {
      ...VIEW,
      scope: { runs: 0, cases: 0, from: null, to: null },
      byPath: [],
      total: { path: 'ALL', runs: 0, attacks: 0, existingMissed: 0, contexaStopped: 0, normals: 0, falseBlocks: 0, contexaShare: null },
    };
    open();

    expect(await screen.findByText(word('bench.agent.empty'))).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: word('bench.agent.paths') })).not.toBeInTheDocument();
  });
});
