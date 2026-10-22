import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { RecapLine } from '../../api/journey';
import i18n from '../../i18n';
import ChangePage from './ChangePage';
import DiffPage from './DiffPage';
import RuleSwitchPage from './RuleSwitchPage';
import RunsPage from './RunsPage';
import SummaryPage from './SummaryPage';

/** A run of the visitor as the journey lists it. */
function run(
  scenarioKey: string,
  engineAction: string,
  exposedItems: number,
  business: Readonly<Record<string, string>>,
): RecapLine {
  return {
    runId: `run-${scenarioKey.toLowerCase()}`,
    scenarioKey,
    classification: scenarioKey === 'S13T' ? 'NORMAL' : 'THREAT',
    status: 'COMPLETED',
    lab: false,
    business,
    engineAction,
    exposedItems,
    correct: true,
    requestedItems: 480,
    steps: scenarioKey === 'S16' ? 3 : 1,
  };
}

/** The visitor's three runs as recorded in the review: the attack checked, the owner allowed, the insider stopped late. */
const RUNS: readonly RecapLine[] = [
  run('S13', 'CHALLENGE', 0, { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'STOPPED' }),
  run('S13T', 'ALLOW', 480, { A: 'PASSED', B: 'PASSED', C1: 'PASSED', C2: 'PASSED', D: 'PASSED' }),
  run('S16', 'ALLOW', 2, { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'PARTLY_STOPPED' }),
];

/** 6-2's run after the hour changed to the dawn: a lab run, so no ground truth; the fixed rule stopped it. */
const AFTER: RecapLine = {
  ...run('S13', 'ALLOW', 480, {
    A: 'NOT_SCORED',
    B: 'NOT_SCORED',
    C1: 'NOT_SCORED',
    C2: 'NOT_SCORED',
    D: 'NOT_SCORED',
  }),
  runId: 'run-after',
  lab: true,
};

const layer = (outcome: 'DELIVERED' | 'STOPPED', deliveredItems: number) => ({
  outcome,
  httpStatus: outcome === 'DELIVERED' ? 200 : 403,
  deliveredItems,
  elapsedMs: 20,
});

const LIVE = {
  liveRunId: 'live-1',
  scenario: 'S13',
  status: 'COMPLETED',
  queuePosition: 0,
  queueWaitSeconds: null,
  runId: 'run-after',
  readyMs: null,
  steps: [
    {
      stepNo: 1,
      operation: 'EXPORT',
      layers: {
        A: layer('DELIVERED', 480),
        B: layer('DELIVERED', 480),
        C1: layer('STOPPED', 0),
        C2: layer('DELIVERED', 480),
        D: layer('DELIVERED', 480),
      },
    },
  ],
  challenge: null,
  failure: null,
};

const BENCHMARK = {
  scope: {
    runs: 44,
    attackRuns: 23,
    normalRuns: 19,
    otherRuns: 2,
    cases: 41,
    fewestRunsPerCase: 1,
    mostRunsPerCase: 2,
    protocols: [{ protocolId: 'protocol-7b925e8e', repeat: 5, finishedAt: '2026-10-20T12:42:36Z' }],
  },
  caseCounts: { THREAT: 21, NORMAL: 18, UNCERTAIN: 2 },
  controls: [],
  cases: [],
  suites: [{ suite: 'RULE_BLIND', cases: ['S13', 'S13T', 'S16'] }],
};

/** The two designed cases of 4-3 as the lab lists them: the same request, only the device apart. */
function labCase(key: string, device: 'NEW' | 'USUAL') {
  return {
    key,
    version: 1,
    title: {},
    classification: key === 'S13' ? 'THREAT' : 'NORMAL',
    steps: 1,
    conditions: { employee: 'eng-k', timeSlot: 'AFTERNOON', place: 'OFFICE', device },
    facts: [],
    requests: [{ operation: 'EXPORT', project: 'HX-310', items: 480, document: null }],
  };
}

const OPTIONS = {
  employees: [{ key: 'eng-k', displayName: 'Engineer K' }],
  timeSlots: [{ slot: 'AFTERNOON', representativeTime: '14:20' }],
  items: [480],
  operations: [],
  cases: [labCase('S13', 'NEW'), labCase('S13T', 'USUAL')],
  calls: [],
  assessmentReasons: [],
};

let predictions: readonly unknown[] = [];

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  predictions = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 6, step: 'compare', differences: [] },
          runs: [...RUNS, AFTER],
          predictions,
        },
        '/api/benchmark': BENCHMARK,
        '/api/lab/options': OPTIONS,
        '/api/live/runs/current': LIVE,
        '/api/runs/run-s13t/steps/1/input-changes?against=run-s13': [
          { key: 'dim.device', before: 'Safari/18 on MAC · false', now: 'Edge/140 on WINDOWS · true' },
        ],
      };
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open(page: ReactElement, path = '/') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={page} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// Review before the guide videos (2026-10-21).
describe('4-3, one line apart', () => {
  it('names the one engine input that differs, Contexa by its decision, and the rule-blind footnote', async () => {
    open(<DiffPage />);
    expect(
      await screen.findByText(i18n.t('main.4-3.intro.one', { name: i18n.t('dim.device') })),
    ).toBeInTheDocument();
    // V-06: the attack's extra check reads as such, with nothing out; the owner's run as allowed with 480 out.
    expect(screen.getByText('추가 인증 · 0건 나감')).toBeInTheDocument();
    expect(screen.getByText('허용 · 480건 나감')).toBeInTheDocument();
    // V-12: the deck's footnote stays, and the two rule-blind cases are said not to be in its conditions.
    expect(
      screen.getByText(`${i18n.t('main.4-3.c2Note')} ${i18n.t('main.4-3.blindNote')}`),
    ).toBeInTheDocument();
  });
});

describe('6-1, the fixed rule turned on', () => {
  it("names Contexa by its decision with the items out, never as 'blocked' for an extra check (V-06)", async () => {
    open(<RuleSwitchPage />);
    expect(await screen.findByText('추가 인증 · 0건 나감')).toBeInTheDocument();
    expect(screen.getByText('허용 · 480건 나감')).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('main.result.STOPPED'))).toBeNull();
  });

  it('says the switch changes nothing when the rule met neither request (V-32)', async () => {
    open(<RuleSwitchPage />);
    expect(await screen.findByText(i18n.t('main.6-1.same'))).toBeInTheDocument();
  });

  // Review before the guide videos (2026-10-21, L-38): the first run badge carried the page's note and no name.
  it('names both run badges alike and says once, apart from them, that nothing was recomputed', async () => {
    open(<RuleSwitchPage />);
    expect(await screen.findByRole('button', { name: new RegExp(i18n.t('main.4-3.attack')) })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: new RegExp(i18n.t('main.4-3.normal')) })).toBeInTheDocument();
    expect(screen.getByText(i18n.t('main.6-1.source')).closest('button')).toBeNull();
  });
});

describe('6-2, one condition changed', () => {
  it('names every approach of the run after by what it did, marked as having no set answer (V-05, V-06)', async () => {
    open(<ChangePage />, '/compare/change?change=time&sent=live-1');
    expect(await screen.findByText(i18n.t('main.6-2.unscored'))).toBeInTheDocument();
    expect(screen.getByText(new RegExp(i18n.t('main.6-2.noAnswer')))).toBeInTheDocument();
    // The run before keeps its scored results; Contexa's cell is its decision with the items out.
    expect(screen.getByText('추가 인증 · 0건 나감')).toBeInTheDocument();
    // The run after: the fixed rule stopped it, the approval-record rule and Contexa let 480 items out; no 'missed'.
    expect(screen.getByText('차단 · 0건 나감')).toBeInTheDocument();
    expect(screen.getAllByText('허용 · 480건 나감')).toHaveLength(2);
  });

  // Review before the guide videos (2026-10-21, L-38): before the send two gold buttons asked to be pressed, the right
  // half held one grey line, and the presets' name was read twice.
  it('before the send: one gold button (the send), the way on quiet, the five lanes waiting unsent', async () => {
    open(<ChangePage />, '/compare/change?change=time');
    const send = await screen.findByRole('button', { name: i18n.t('main.6-2.send') });
    expect(send).not.toHaveAttribute('data-quiet');
    expect(document.querySelector('[data-zone="actions"] [data-main]')).toHaveAttribute('data-quiet');
    expect(screen.getAllByText(i18n.t('main.4-4.notYet'))).toHaveLength(5);
    expect(screen.getAllByText(i18n.t('main.6-2.controls'))).toHaveLength(1);
  });

  it('after the send: the way on is the gold button and sending again is quiet', async () => {
    open(<ChangePage />, '/compare/change?change=time&sent=live-1');
    await screen.findByText(i18n.t('main.6-2.unscored'));
    expect(screen.getByRole('button', { name: i18n.t('main.6-2.send') })).toHaveAttribute('data-quiet');
    expect(document.querySelector('[data-zone="actions"] [data-main]')).not.toHaveAttribute('data-quiet');
  });
});

describe('6-3, every repeated run', () => {
  it('names the disputed runs that have no dot beside the count of runs, and no measurement id (V-11, V-48)', async () => {
    open(<RunsPage />);
    expect(
      await screen.findByText(i18n.t('main.6-3.uncertain', { cases: 2, runs: 2, count: 2 }), {
        exact: false,
      }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/protocol-7b925e8e/)).toBeNull();
  });
});

describe('7-1, what you confirmed', () => {
  // Review before the guide videos (2026-10-21, V-37): an extra check counted as 'stopped' without saying so.
  it('says under the calls that an extra check counts as the call that the request is stopped', async () => {
    predictions = [{ experience: 'E1', engineActual: 'CHALLENGE', engineSameStop: true }];
    open(<SummaryPage />);
    expect(await screen.findByText(i18n.t('main.7-1.call.note'))).toBeInTheDocument();
  });

  it("names the insider's result under the calls (V-40)", async () => {
    open(<SummaryPage />);
    expect(
      await screen.findByText(i18n.t('main.7-1.insider.PARTLY_STOPPED', { n: '2', count: 2 })),
    ).toBeInTheDocument();
  });
});
