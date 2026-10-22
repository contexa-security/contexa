import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ResultPage from './ResultPage';

const RUN = 'run-e7177ebe6785';

/** A layer of the attack run's stored step result: what the approach let out. */
function layer(control: string, outcome: string, httpStatus: number, deliveredItems: number) {
  return {
    control,
    outcome,
    verdict: null,
    httpStatus,
    ruleId: null,
    reason: null,
    ruleFacts: {},
    evidence: { deliveredItems, responseMs: 30 },
  };
}

/** The visitor's attack run as the portal stored it: every existing approach let 480 items out, Contexa none. */
const BODIES: Readonly<Record<string, unknown>> = {
  '/api/visitor': { predictions: {} },
  '/api/journey': {
    state: { route: 'DEFAULT', act: 2, step: 'attack-result', differences: [] },
    runs: [
      {
        runId: RUN,
        scenarioKey: 'S13',
        classification: 'THREAT',
        status: 'COMPLETED',
        lab: false,
        business: { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'STOPPED' },
        engineAction: 'CHALLENGE',
        exposedItems: 0,
        correct: true,
        requestedItems: 480,
        steps: 1,
      },
    ],
    predictions: [],
  },
  [`/api/runs/${RUN}/steps/1/result`]: {
    companyTime: '2026-09-30T14:20:00Z',
    layers: [
      layer('A', 'DELIVERED', 200, 480),
      layer('B', 'DELIVERED', 200, 480),
      layer('C1', 'DELIVERED', 200, 480),
      layer('C2', 'DELIVERED', 200, 480),
      layer('D', 'STOPPED', 401, 0),
    ],
    engineReason: null,
    companyFacts: [],
    tally: {},
    existingTally: {},
  },
  [`/api/runs/${RUN}/steps/1/anatomy`]: {
    interpretation: { recorded: { finalAction: 'CHALLENGE' }, calls: [], timeline: [], sinceStartMs: [] },
    learning: null,
  },
  [`/api/runs/${RUN}/steps/1/received`]: {
    runId: RUN,
    usualVsNow: [
      { dimension: 'device', now: 'Safari/18 on MAC', inUsual: 'false', labels: ['DeviationsFromBaseline'] },
      { dimension: 'size', now: '480 items', inUsual: 'false', labels: ['DeviationsFromBaseline'] },
    ],
    usual: { device: { label: 'UsualDevices', values: ['Edge/140 on WINDOWS'] } },
    departureCount: 2,
    businessFacts: [
      { code: 'ASSIGNED', value: 'HX-310' },
      { code: 'NO_APPROVAL', value: null },
    ],
    sizeRatio: { items: 480, usualLargest: 15, times: 32 },
  },
};

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = BODIES[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
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
      <MemoryRouter initialEntries={['/attack/result']}>
        <Routes>
          <Route path="*" element={<ResultPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// Review before the guide videos (2026-10-21, V-07): the company records card read as a third reason with a green check
// for a rule that let the attack through.
describe('the company records on the result of the attack', () => {
  it('are a reference, not a numbered reason, and the rule that let the attack through reads as a miss', async () => {
    open();
    const rule = i18n.t('main.lane.C2');
    const passed = await screen.findByText(i18n.t('main.2-3.company.passed', { rule }));
    expect(passed).toHaveTextContent('미탐');
    const card = passed.closest('section');
    expect(card).toHaveAttribute('data-reference');
    expect(card?.querySelector('[data-ok]')).toBeNull();
    expect(screen.getByText(i18n.t('main.2-3.company.label'))).not.toHaveTextContent('③');
  });
});
