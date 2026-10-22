import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import InsidePage from './InsidePage';

/** The insider's measured run as the portal stores it: request 1 allowed, request 2 blocked, request 3 refused. */
const RUN = 'run-insider';

function anatomy(stepNo: number, action: string, risk: number, reasoning: string) {
  return {
    runId: RUN,
    stepNo,
    interpretation: {
      calls: [],
      recorded: {
        proposedAction: action,
        finalAction: action,
        riskScore: risk,
        confidence: 0.8,
        reasoning,
        reasoningCode: null,
        mitre: null,
        unresolved: false,
        failureType: null,
        fallbackCategory: null,
        applied: 'NEXT_REQUEST',
        evidenceRefs: [],
      },
    },
  };
}

const BODIES: Readonly<Record<string, unknown>> = {
  '/api/visitor': { predictions: {} },
  '/api/journey': { state: { route: 'DEFAULT', act: 5, step: 'insider-reason', differences: [] }, runs: [] },
  '/api/benchmark': {
    scope: { protocols: [{ protocolId: 'protocol-x', finishedAt: '2026-10-20T12:42:36Z' }] },
    suites: [{ suite: 'RULE_BLIND', cases: ['S13', 'S13T', 'S16', 'S16T'] }],
    cases: [
      {
        key: 'S16',
        runs: 1,
        runIds: [RUN],
        results: { C1: { MISSED: 1 }, C2: { MISSED: 1 }, D: { PARTLY_STOPPED: 1 } },
        runResults: { [RUN]: { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'PARTLY_STOPPED' } },
      },
      {
        key: 'S16T',
        runs: 1,
        runIds: [],
        results: { C1: { PASSED: 1 }, C2: { PASSED: 1 }, D: { PASSED: 1 } },
      },
    ],
  },
  [`/api/runs/${RUN}/score`]: {
    runId: RUN,
    executedSteps: 3,
    business: { D: { result: 'PARTLY_STOPPED', exposedItems: 2, worstStep: 1 } },
    verdicts: [
      { score: { stepNo: 1, finalAction: 'ALLOW', applied: 'NEXT_REQUEST' }, source: 'MODEL' },
      { score: { stepNo: 2, finalAction: 'BLOCK', applied: 'NEXT_REQUEST' }, source: 'MODEL' },
      { score: { stepNo: 3, finalAction: null, applied: 'NONE' }, source: 'PRIOR_DECISION' },
    ],
  },
  [`/api/runs/${RUN}/steps/1/anatomy`]: anatomy(1, 'ALLOW', 0.24, 'Legitimate work is most likely.'),
  [`/api/runs/${RUN}/steps/2/anatomy`]: anatomy(
    2,
    'BLOCK',
    0.82,
    'Sales documents unrelated to design work.',
  ),
  [`/api/runs/${RUN}/steps/2/quality`]: {
    available: true,
    reason: null,
    bundle: null,
    seal: null,
    inspection: null,
    ribbon: null,
    hypotheses: [],
    reasonCodes: [
      { code: 'DATA_NATURE_MISMATCH', fact: 'R4' },
      { code: 'ASSIGNED_TARGET', fact: 'F4' },
    ],
  },
  [`/api/runs/${RUN}/steps/1/result`]: { layers: [{ control: 'D', outcome: 'DELIVERED' }] },
  [`/api/runs/${RUN}/steps/2/result`]: { layers: [{ control: 'D', outcome: 'DELIVERED' }] },
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

function open(path = '/insider/reason') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={<InsidePage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function hero() {
  return screen.getByRole('region', { name: i18n.t('main.verdictCard.label') });
}

// Review before the guide videos (2026-10-21), V-02: the decision that stopped the insider was shown nowhere.
describe('5-3, the insider judgment shown', () => {
  it('opens on the decision that stopped the insider and names its request in the conclusion', async () => {
    open();
    const request2 = await screen.findByRole('radio', {
      name: new RegExp(i18n.t('main.4-4.step', { n: 2 })),
    });
    expect(request2).toBeChecked();
    expect(within(hero()).getByText(i18n.t('main.verdict.BLOCK'))).toBeInTheDocument();
    expect(
      screen.getByText(
        i18n.t('main.5-3.intro.proof', { step: 2, n: 2, verdict: i18n.t('main.verdict.BLOCK') }),
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(i18n.t('main.5-3.after', { count: 2, n: 2 }))).toBeInTheDocument();
  });

  it('lets the visitor pick request 1, whose allowing judgment points to the request that stopped it', async () => {
    open();
    const request1 = await screen.findByRole('radio', {
      name: new RegExp(i18n.t('main.4-4.step', { n: 1 })),
    });
    await userEvent.click(request1);
    expect(await within(hero()).findByText(i18n.t('main.verdict.ALLOW'))).toBeInTheDocument();
    expect(
      screen.getByText(
        i18n.t('main.5-3.intro.other', { step: 1, verdict: i18n.t('main.verdict.ALLOW'), held: 2 }),
      ),
    ).toBeInTheDocument();
    // The refused request 3 has no judgment of its own to pick.
    expect(screen.queryByRole('radio', { name: new RegExp(i18n.t('main.4-4.step', { n: 3 })) })).toBeNull();
  });

  it('says what a measured count is a count of, names no case number and explains the rule marked *', async () => {
    open();
    await screen.findByRole('radio', { name: new RegExp(i18n.t('main.4-4.step', { n: 2 })) });
    expect(
      screen.getAllByText(
        i18n.t('main.5-3.count', { word: i18n.t('main.result.MISSED'), n: 1, runs: 1, count: 1 }),
      ),
    ).toHaveLength(2);
    expect(screen.queryByText(/S16/)).toBeNull();
    expect(
      screen.getByText(`${i18n.t('main.4-3.c2Note')} ${i18n.t('main.4-3.blindOne')}`),
    ).toBeInTheDocument();
  });
});
