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

// 구현계획 NW-8: the reasons moved to their own screen (2-4); the result keeps the headline and the proof of the five approaches.
describe('the result of the attack', () => {
  it("says what Contexa did in the headline of the visitor's own run and leaves the reasons to the next screen", async () => {
    open();
    expect(await screen.findByRole('heading', { level: 1, name: i18n.t('main.2-3.title.CHALLENGE') })).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('main.2-3.company.label'))).toBeNull();
    expect(screen.queryByText(i18n.t('main.2-3.size.label'))).toBeNull();
  });

  // 구현계획 NW-8: what each approach answered is in view; the proof of the record and the learning fold under one line.
  it('keeps what each approach answered in view and folds the proof and the learning under one line', async () => {
    const { container } = open();
    await screen.findByRole('heading', { level: 1, name: i18n.t('main.2-3.title.CHALLENGE') });
    const fold = container.querySelector('details[data-fold="proof"]') as HTMLDetailsElement | null;
    expect(fold).not.toBeNull();
    expect(fold?.open).toBe(false);
    expect(fold?.textContent).toContain(i18n.t('main.proof.fold'));
    expect(fold?.textContent).toContain(i18n.t('main.proof.check.title'));
    expect(fold?.textContent).toContain(i18n.t('main.proof.learn.title'));
    // the bars of the five approaches are outside the fold
    const out = screen.getByText(i18n.t('main.proof.out.title'));
    expect(fold?.contains(out)).toBe(false);
  });
});
