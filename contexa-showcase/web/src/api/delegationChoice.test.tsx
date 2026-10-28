import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { choiceQuery, useDelegationChoice, type DelegationChoice } from './agentCase';

/**
 * docs/agent Agent중심-화면 AS-12: the delegation a visitor edits is named in the address (the lab's link) and read only
 * when the portal's lists hold it, for the one case whose delegation may be edited; anything else is the case as it is.
 */
const EDIT = {
  case: 'ED1',
  title: { ko: '위임장 편집', en: 'Delegation edit' },
  quantities: [40, 100, 400],
  periods: ['VALID', 'EXPIRED', 'REVOKED'],
  operations: ['READ_ONLY', 'READ_EXPORT'],
};

let bodies: Record<string, unknown>;

beforeEach(() => {
  bodies = {
    '/api/visitor': { predictions: {} },
    '/api/live/config': {
      scenarios: [],
      agentCases: [{ key: 'T5', title: { ko: 'T5', en: 'T5' }, classification: 'THREAT', subject: 'AGENT' }],
      delegationEdit: EDIT,
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

function Probe({ caseKey }: { readonly caseKey: string }) {
  return <p data-testid="choice">{JSON.stringify(useDelegationChoice(caseKey))}</p>;
}

function open(path: string, caseKey = 'ED1') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Probe caseKey={caseKey} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const NONE: DelegationChoice = { quantity: null, period: null, operations: null };

async function settled(expected: DelegationChoice) {
  await vi.waitFor(() => expect(JSON.parse(screen.getByTestId('choice').textContent ?? 'null')).toEqual(expected));
}

describe('the delegation choice the address names (AS-12)', () => {
  it('is no choice when the address names none', async () => {
    open('/agent/request?case=ED1');

    await settled(NONE);
  });

  it('reads the three values of the lists', async () => {
    open('/agent/request?case=ED1&quantity=400&period=EXPIRED&operations=READ_ONLY');

    await settled({ quantity: 400, period: 'EXPIRED', operations: 'READ_ONLY' });
  });

  it('reads one value alone and leaves the others as the case has them', async () => {
    open('/agent/request?case=ED1&period=REVOKED');

    await settled({ quantity: null, period: 'REVOKED', operations: null });
  });

  it('ignores a value the lists do not hold', async () => {
    open('/agent/request?case=ED1&quantity=401&period=FOREVER&operations=ALL');

    await new Promise((resolve) => setTimeout(resolve, 50));
    await settled(NONE);
  });

  it('is no choice for any case but the editable one', async () => {
    open('/agent/request?case=T5&quantity=400', 'T5');

    await new Promise((resolve) => setTimeout(resolve, 50));
    await settled(NONE);
  });

  it('is no choice when the portal offers no edit', async () => {
    delete (bodies['/api/live/config'] as Record<string, unknown>)['delegationEdit'];
    open('/agent/request?case=ED1&quantity=400');

    await new Promise((resolve) => setTimeout(resolve, 50));
    await settled(NONE);
  });
});

describe('the query that carries a choice to the portal', () => {
  it('names only the values that are set, and nothing for no choice', () => {
    expect(choiceQuery(NONE)).toBe('');
    expect(choiceQuery({ quantity: 400, period: null, operations: null })).toBe('?quantity=400');
    expect(choiceQuery({ quantity: 100, period: 'EXPIRED', operations: 'READ_ONLY' })).toBe(
      '?quantity=100&period=EXPIRED&operations=READ_ONLY',
    );
  });
});
