import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAgentCaseKey } from './agentCase';

/**
 * docs/agent Agent중심-화면 AS-14: the agent group's screens follow the case the visitor works with, among the cases the
 * portal opens (T5 until a visitor picks another): the case chosen in the address, else the visitor's live run, else the
 * latest agent run of the journey, else T5. A case the portal does not open is never followed.
 */
const OPEN = ['T5', 'N1', 'M14A'];

let bodies: Record<string, unknown>;

beforeEach(() => {
  bodies = {
    '/api/visitor': { predictions: {} },
    '/api/live/config': {
      scenarios: [],
      agentCases: OPEN.map((key) => ({ key, title: { ko: key, en: key }, classification: 'THREAT', subject: 'AGENT' })),
      turnstileSiteKey: null,
      dailyRuns: 10,
      remainingToday: 10,
      paused: false,
    },
    '/api/live/runs/current': null,
    '/api/journey': { state: { route: 'DEFAULT', act: 6, step: 'agent', differences: [] }, runs: [], predictions: [] },
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
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

function Probe() {
  return <p data-testid="key">{useAgentCaseKey()}</p>;
}

function open(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Probe />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function settled(expected: string) {
  await vi.waitFor(() => expect(screen.getByTestId('key').textContent).toBe(expected));
}

describe('the case the agent screens follow (AS-14)', () => {
  it('is T5 when nothing says otherwise', async () => {
    open('/agent/request');

    await settled('T5');
  });

  it('is the case the address names when the portal opens it', async () => {
    open('/agent/request?case=N1');

    await settled('N1');
  });

  it('never follows a case the portal does not open', async () => {
    open('/agent/request?case=M99');

    // the config has answered when the open cases are known; the key stays T5
    await new Promise((resolve) => setTimeout(resolve, 50));
    await settled('T5');
  });

  it('follows the visitor\'s live run of an open case when the address names none', async () => {
    bodies['/api/live/runs/current'] = {
      liveRunId: 'live-1',
      scenario: 'M14A',
      status: 'RUNNING',
      steps: [],
      queuePosition: null,
    };
    open('/agent/console');

    await settled('M14A');
  });

  it('follows the latest agent run of the journey when no run is going', async () => {
    bodies['/api/journey'] = {
      state: { route: 'DEFAULT', act: 6, step: 'agent', differences: [] },
      runs: [
        { runId: 'run-aaaaaaaaaaaa', scenarioKey: 'T5', status: 'COMPLETED' },
        { runId: 'run-bbbbbbbbbbbb', scenarioKey: 'A3', status: 'COMPLETED' },
        { runId: 'run-cccccccccccc', scenarioKey: 'N1', status: 'COMPLETED' },
      ],
      predictions: [],
    };
    open('/agent/result');

    await settled('N1');
  });

  it('lets the address win over a run of another case, so a visitor can pick a case again', async () => {
    bodies['/api/live/runs/current'] = {
      liveRunId: 'live-1',
      scenario: 'N1',
      status: 'COMPLETED',
      steps: [],
      queuePosition: null,
    };
    open('/agent/request?case=T5');

    await settled('T5');
  });
});
