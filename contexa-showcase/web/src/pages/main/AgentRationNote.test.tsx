import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import AgentRequestPage from './AgentRequestPage';
import { T5_CONFIRM_APPROVE } from './agentSnapshotFixture';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

const CONFIG = {
  scenarios: [],
  agentCases: [],
  turnstileSiteKey: null,
  dailyRuns: 10,
  remainingToday: 10,
  agentRunPoints: 3,
  dailyAgentRuns: 2,
  remainingAgentToday: 2,
  paused: false,
};

let bodies: Record<string, unknown>;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  bodies = {
    '/api/visitor': { predictions: {} },
    '/api/journey': { state: { route: 'DEFAULT', act: 6, step: 'agent', differences: [] }, runs: [], predictions: [] },
    '/api/agent-cases/T5': T5_CONFIRM_APPROVE.case,
    '/api/live/config': { ...CONFIG, liveTicketsLeft: 7, agentConcurrent: 5, agentRunsActive: 1 },
  };
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
      <MemoryRouter initialEntries={['/agent/request']}>
        <Routes>
          <Route path="*" element={<AgentRequestPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** docs/agent Agent중심-화면 AC-6, D-7: a real run is told apart from a stored one, with the day's share that is left. */
describe('6-1 tells the day\'s share of real runs (AC-6)', () => {
  it('says this send is a real run and how many real runs are left today', async () => {
    open();

    const left = await screen.findByText(word('main.6-1.live').replace('{{n}}', '7'));
    expect(left).toBeInTheDocument();
    // the count is a detail: it stays under the fold, and the first view says only when the runs are gone
    expect(left.closest('details[data-fold="agent-work"]')).not.toBeNull();
    expect(screen.queryByText(word('main.6-1.liveNone'))).not.toBeInTheDocument();
  });

  it('says plainly when the day\'s real runs are all gone and leads to the stored runs', async () => {
    bodies['/api/live/config'] = { ...CONFIG, liveTicketsLeft: 0, agentConcurrent: 5, agentRunsActive: 0 };
    open();

    const gone = await screen.findByText(word('main.6-1.liveNone'), { exact: false });
    expect(gone.closest('details')).toBeNull();
    expect(screen.getByRole('link', { name: word('main.6-1.liveStored') })).toHaveAttribute('href', '/agent/reason');
    expect(screen.queryByText(/오늘 .*회 더 보낼 수 있습니다/)).not.toBeInTheDocument();
  });

  it('says nothing of a share when the portal does not count one', async () => {
    bodies['/api/live/config'] = CONFIG;
    open();

    expect(await screen.findByText(word('main.6-1.send'))).toBeInTheDocument();
    expect(screen.queryByText(word('main.6-1.liveNone'))).not.toBeInTheDocument();
    expect(screen.queryByText(/실제 실행 · 오늘/)).not.toBeInTheDocument();
  });
});
