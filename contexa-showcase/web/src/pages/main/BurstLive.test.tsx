import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { BurstSummary } from '../../api/agentCase';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { BurstLive } from './BurstLive';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string, values: Record<string, string | number> = {}): string {
  return Object.entries(values).reduce(
    (text, [name, value]) => text.replace(`{{${name}}}`, String(value)),
    required(KO[key], key),
  );
}

/**
 * docs/agent Agent중심-화면 AS-13, AC-7b: 6-6 lets a visitor send a burst of the same request live, up to the most the portal
 * offers (ten). The number goes with the start and nothing else of it; the visitor stays on the screen, sees that the run
 * goes, and reads the counts the portal made of their own run in the rows of the stored measurements. When the day's
 * share of live runs is spent the screen says so and leads to the stored measurements.
 */
const BURST = {
  case: 'M41A',
  title: { ko: '같은 목록 요청을 한꺼번에', en: 'The same list request at once' },
  most: 10,
  measured: 60,
  points: 5,
};

const OWN: BurstSummary = {
  requests: 16,
  delivered: 16,
  refused: 0,
  busy: 0,
  withVerdict: 6,
  modelCalls: 7,
  firstStopStep: null,
  deliveredAfterFirstStop: 0,
};

function config(overrides: Record<string, unknown> = {}) {
  return {
    scenarios: [],
    agentCases: [],
    burst: BURST,
    turnstileSiteKey: null,
    dailyRuns: 10,
    remainingToday: 10,
    agentRunPoints: 3,
    dailyAgentRuns: 2,
    remainingAgentToday: 2,
    liveTicketsLeft: 7,
    paused: false,
    ...overrides,
  };
}

let bodies: Record<string, unknown>;
let posted: { url: string; body: unknown }[];
let fetched: string[];
let postAnswer: { status: number; body: unknown };

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  posted = [];
  fetched = [];
  postAnswer = {
    status: 202,
    body: { liveRunId: 'live-1', scenario: 'M41A', status: 'RUNNING', steps: [], runId: null },
  };
  bodies = {
    '/api/visitor': { predictions: {} },
    '/api/journey': {
      state: { route: 'DEFAULT', act: 6, step: 'agent', differences: [] },
      runs: [],
      predictions: [],
    },
    '/api/live/runs/current': null,
    '/api/live/config': config(),
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        posted.push({ url, body: JSON.parse(String(init.body ?? 'null')) });
        return new Response(JSON.stringify(postAnswer.body), { status: postAnswer.status });
      }
      fetched.push(url);
      const body = bodies[url];
      return new Response(body === undefined || body === null ? null : JSON.stringify(body), {
        status: body === undefined || body === null ? 404 : 200,
      });
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
      <MemoryRouter initialEntries={['/agent/burst']}>
        <Routes>
          <Route path="*" element={<BurstLive />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('6-6, a burst the visitor sends live (AS-13)', () => {
  it('shows nothing while the portal offers no burst', async () => {
    bodies['/api/live/config'] = config({ burst: undefined });
    const { container } = open();

    await vi.waitFor(() => expect(fetched).toContain('/api/live/config'));
    expect(container).toBeEmptyDOMElement();
  });

  // 구현계획 AC-N2: the measured bursts are what 6-6 shows first; the visitor's own send waits under one line.
  it('waits under one line while nothing runs, and opens by itself once the visitor sends', async () => {
    const { container } = open();
    await screen.findByRole('radiogroup', { name: word('main.6-6.live.count') });
    const fold = container.querySelector('details[data-fold="burst-live"]') as HTMLDetailsElement | null;
    expect(fold).not.toBeNull();
    expect(fold?.open).toBe(false);
    expect(fold?.textContent).toContain(word('main.6-6.live.title'));
  });

  it('is open while its run goes', async () => {
    bodies['/api/live/runs/current'] = {
      liveRunId: 'live-1',
      scenario: 'M41A',
      status: 'RUNNING',
      steps: [],
      runId: null,
    };
    const { container } = open();
    await screen.findByText(word('main.6-6.live.running'));
    expect((container.querySelector('details[data-fold="burst-live"]') as HTMLDetailsElement).open).toBe(
      true,
    );
  });

  it('offers the numbers up to the most the portal allows, with ten chosen, and says what a burst costs', async () => {
    open();

    const group = await screen.findByRole('radiogroup', { name: word('main.6-6.live.count') });
    const names = within(group)
      .getAllByRole('radio')
      .map((radio) => radio.getAttribute('value'));
    expect(names).toEqual(['1', '3', '5', '10']);
    expect(
      within(group).getByRole('radio', { name: word('main.6-6.live.countValue', { n: 10 }) }),
    ).toBeChecked();
    expect(screen.getByText(word('main.6-6.live.intro', { most: 10 }))).toBeInTheDocument();
    expect(screen.getByText(word('main.6-6.live.cost', { points: 5, runs: 2 }))).toBeInTheDocument();
    // the button opens once the visitor is known
    await vi.waitFor(() =>
      expect(screen.getByRole('button', { name: word('main.6-6.live.send', { n: 10 }) })).toBeEnabled(),
    );
  });

  it('never offers a number above what the portal allows, whatever the portal says it allows', async () => {
    bodies['/api/live/config'] = config({ burst: { ...BURST, most: 4 } });
    open();

    const group = await screen.findByRole('radiogroup', { name: word('main.6-6.live.count') });
    expect(
      within(group)
        .getAllByRole('radio')
        .map((radio) => radio.getAttribute('value')),
    ).toEqual(['1', '3', '4']);
  });

  it('sends the chosen number with the start, as the case named by the portal, and nothing else of it', async () => {
    open();
    const user = userEvent.setup();

    await user.click(await screen.findByRole('radio', { name: word('main.6-6.live.countValue', { n: 3 }) }));
    await user.click(screen.getByRole('button', { name: word('main.6-6.live.send', { n: 3 }) }));

    await vi.waitFor(() => expect(posted.some((call) => call.url === '/api/live/runs')).toBe(true));
    expect(posted.find((call) => call.url === '/api/live/runs')?.body).toEqual({
      scenario: 'M41A',
      turnstileToken: null,
      copies: 3,
    });
  });

  it('stays on the screen while the run goes and says so', async () => {
    bodies['/api/live/runs/current'] = {
      liveRunId: 'live-1',
      scenario: 'M41A',
      status: 'RUNNING',
      steps: [],
      runId: null,
    };
    open();

    expect(await screen.findByText(word('main.6-6.live.running'))).toBeInTheDocument();
    expect(screen.getByRole('button', { name: word('main.6-6.live.sending') })).toBeDisabled();
  });

  it('shows the counts the portal made of the visitor’s own burst in the rows of the stored measurements', async () => {
    bodies['/api/live/runs/current'] = {
      liveRunId: 'live-1',
      scenario: 'M41A',
      status: 'COMPLETED',
      steps: [],
      runId: 'run-0123456789ab',
    };
    bodies['/api/runs/run-0123456789ab/agent'] = { runId: 'run-0123456789ab', steps: [], burst: OWN };
    open();

    const own = within(await screen.findByRole('region', { name: word('main.6-6.own.title') }));
    const rows = own.getAllByRole('row').map((row) => row.textContent ?? '');
    expect(rows.find((row) => row.startsWith(word('main.6-6.row.requests')))).toBe(
      `${word('main.6-6.row.requests')}16`,
    );
    expect(rows.find((row) => row.startsWith(word('main.6-6.row.withVerdict')))).toBe(
      `${word('main.6-6.row.withVerdict')}6`,
    );
    expect(rows.find((row) => row.startsWith(word('main.6-6.row.modelCalls')))).toBe(
      `${word('main.6-6.row.modelCalls')}7`,
    );
    expect(rows.find((row) => row.startsWith(word('main.6-6.row.firstStopStep')))).toBe(
      `${word('main.6-6.row.firstStopStep')}${word('main.6-7.neverStopped')}`,
    );
    expect(own.getByText(word('main.6-6.own.note'))).toBeInTheDocument();
  });

  it('says a run that did not reach its end gave its points back, and shows no counts for it', async () => {
    bodies['/api/live/runs/current'] = {
      liveRunId: 'live-1',
      scenario: 'M41A',
      status: 'FAILED',
      steps: [],
      runId: null,
    };
    open();

    expect(await screen.findByText(word('main.6-6.live.failed'))).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: word('main.6-6.own.title') })).not.toBeInTheDocument();
  });

  it('leads to the stored measurements when the day’s share of live runs is spent, and sends nothing', async () => {
    bodies['/api/live/config'] = config({ liveTicketsLeft: 0 });
    open();

    expect(await screen.findByText(word('main.6-6.live.noTickets'))).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('main.6-6.live.toMeasured') })).toHaveAttribute(
      'href',
      '#burst-measured',
    );
    expect(screen.getByRole('button', { name: word('main.6-6.live.send', { n: 10 }) })).toBeDisabled();
    expect(posted).toEqual([]);
  });

  it('says so and leads to the stored measurements when the points left are fewer than a burst costs', async () => {
    bodies['/api/live/config'] = config({ remainingToday: 4 });
    open();

    expect(await screen.findByText(word('main.6-6.live.noPoints', { points: 5 }))).toBeInTheDocument();
    expect(screen.getByRole('button', { name: word('main.6-6.live.send', { n: 10 }) })).toBeDisabled();
    expect(screen.getByRole('link', { name: word('main.6-6.live.toMeasured') })).toHaveAttribute(
      'href',
      '#burst-measured',
    );
    expect(posted).toEqual([]);
  });

  it('lets a visitor with exactly the points of a burst send it', async () => {
    bodies['/api/live/config'] = config({ remainingToday: 5 });
    open();

    await vi.waitFor(() =>
      expect(screen.getByRole('button', { name: word('main.6-6.live.send', { n: 10 }) })).toBeEnabled(),
    );
    expect(screen.queryByText(word('main.6-6.live.noPoints', { points: 5 }))).not.toBeInTheDocument();
  });

  it('tells a refusal of the gate in the words of the other live starts', async () => {
    postAnswer = { status: 429, body: { reason: 'AGENT_LIMIT' } };
    open();
    const user = userEvent.setup();

    await user.click(await screen.findByRole('button', { name: word('main.6-6.live.send', { n: 10 }) }));

    expect(await screen.findByText(word('state.dailyLimit'))).toBeInTheDocument();
  });
});
