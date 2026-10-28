import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { RecapLine } from '../../api/journey';
import i18n from '../../i18n';
import { rememberTrack } from '../../journey/trackMemory';
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

/** 7-2's run after the hour changed to the dawn: a lab run, so no ground truth; the fixed rule stopped it. */
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

/** One approach's score in the repeated runs, with what 7-3's title reads: the attacks nothing stopped, the normal work stopped. */
function score(control: string, missed: number, falseBlocks: number) {
  const rate = (hits: number, total: number) => ({ hits, total, rate: hits / total, low: 0, high: 1, preliminary: false });
  return {
    control,
    stopped: rate(0, 23),
    stoppedAny: rate(23 - missed, 23),
    stoppedMacro: null,
    stoppedAnyMacro: null,
    falseBlock: rate(falseBlocks, 19),
    friction: rate(0, 19),
    falseBlockMacro: null,
    attackUnresolved: 0,
    normalUnresolved: 0,
    exposedItems: 0,
    partlyStopped: 0,
    missed,
    normalPassed: 19 - falseBlocks,
    notBlocked: rate(19 - falseBlocks, 19),
  };
}

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
/** The runs the journey lists for the visitor, and the agent cases the portal opens (null: it lists none). */
let visitorRuns: readonly RecapLine[] = [];
let benchmarkBody: unknown = BENCHMARK;
let agentCases: readonly unknown[] | null = null;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  predictions = [];
  visitorRuns = [...RUNS, AFTER];
  benchmarkBody = BENCHMARK;
  agentCases = null;
  window.sessionStorage.clear();
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 7, step: 'compare', differences: [] },
          runs: visitorRuns,
          predictions,
        },
        '/api/benchmark': benchmarkBody,
        ...(agentCases ? { '/api/live/config': { agentCases } } : {}),
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

describe('7-1, the fixed rule turned on', () => {
  it("names Contexa by its decision with the items out, never as 'blocked' for an extra check (V-06)", async () => {
    open(<RuleSwitchPage />);
    expect(await screen.findByText('추가 인증 · 0건 나감')).toBeInTheDocument();
    expect(screen.getByText('허용 · 480건 나감')).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('main.result.STOPPED'))).toBeNull();
  });

  it('says the switch changes nothing when the rule met neither request (V-32)', async () => {
    open(<RuleSwitchPage />);
    expect(await screen.findByText(i18n.t('main.7-1.same'))).toBeInTheDocument();
  });

  // Review before the guide videos (2026-10-21, L-38): the first run badge carried the page's note and no name.
  it('names both run badges alike and says once, apart from them, that nothing was recomputed', async () => {
    open(<RuleSwitchPage />);
    expect(
      await screen.findByRole('button', { name: new RegExp(i18n.t('main.4-3.attack')) }),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: new RegExp(i18n.t('main.4-3.normal')) })).toBeInTheDocument();
    expect(screen.getByText(i18n.t('main.7-1.source')).closest('button')).toBeNull();
  });
});

describe('7-2, one condition changed', () => {
  // 구현계획 AC-N9: before the first send the five waiting lanes, which name the approaches that will answer, sit under one line.
  it('keeps the five waiting lanes under one line before anything was sent', async () => {
    visitorRuns = [];
    const { container } = open(<ChangePage />, '/compare/change');
    expect(await screen.findByText(i18n.t('main.7-2.notSent'))).toBeInTheDocument();
    const fold = container.querySelector('details[data-fold="change-lanes"]') as HTMLDetailsElement | null;
    expect(fold).not.toBeNull();
    expect(fold?.open).toBe(false);
    expect(fold?.querySelectorAll('li[data-control]')).toHaveLength(5);
  });

  it('names every approach of the run after by what it did, marked as having no set answer (V-05, V-06)', async () => {
    open(<ChangePage />, '/compare/change?change=time&sent=live-1');
    expect(await screen.findByText(i18n.t('main.7-2.unscored'))).toBeInTheDocument();
    expect(screen.getByText(new RegExp(i18n.t('main.7-2.noAnswer')))).toBeInTheDocument();
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
    const send = await screen.findByRole('button', { name: i18n.t('main.7-2.send') });
    expect(send).not.toHaveAttribute('data-quiet');
    expect(document.querySelector('[data-zone="actions"] [data-main]')).toHaveAttribute('data-quiet');
    expect(screen.getAllByText(i18n.t('main.4-4.notYet'))).toHaveLength(5);
    expect(screen.getAllByText(i18n.t('main.7-2.controls'))).toHaveLength(1);
  });

  it('after the send: the way on is the gold button and sending again is quiet', async () => {
    open(<ChangePage />, '/compare/change?change=time&sent=live-1');
    await screen.findByText(i18n.t('main.7-2.unscored'));
    expect(screen.getByRole('button', { name: i18n.t('main.7-2.send') })).toHaveAttribute('data-quiet');
    expect(document.querySelector('[data-zone="actions"] [data-main]')).not.toHaveAttribute('data-quiet');
  });
});

describe('7-3, every repeated run', () => {
  // 구현계획 NW-13: the title states what the repeated runs measured, and claims both only when the numbers say both.
  it('states the counts of the measurement as its title when Contexa missed an attack', async () => {
    benchmarkBody = { ...BENCHMARK, controls: [score('D', 2, 0), score('C1', 10, 8)] };
    open(<RunsPage />);
    expect(
      await screen.findByRole('heading', { level: 1, name: i18n.t('main.7-3.titleCounts', { missed: 2, falseBlock: 0 }) }),
    ).toBeInTheDocument();
  });

  it('says Contexa keeps both only when it missed none and blocked none while the fixed rule gave one up', async () => {
    benchmarkBody = { ...BENCHMARK, controls: [score('D', 0, 0), score('C1', 10, 8)] };
    open(<RunsPage />);
    expect(await screen.findByRole('heading', { level: 1, name: i18n.t('main.7-3.title') })).toBeInTheDocument();
  });

  it('names the disputed runs that have no dot beside the count of runs, and no measurement id (V-11, V-48)', async () => {
    open(<RunsPage />);
    expect(
      await screen.findByText(i18n.t('main.7-3.uncertain', { cases: 2, runs: 2, count: 2 }), {
        exact: false,
      }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/protocol-7b925e8e/)).toBeNull();
  });
});

describe('8-1, what you confirmed', () => {
  // Review before the guide videos (2026-10-21, V-37): an extra check counted as 'stopped' without saying so.
  it('says under the calls that an extra check counts as the call that the request is stopped', async () => {
    predictions = [{ experience: 'E1', engineActual: 'CHALLENGE', engineSameStop: true }];
    open(<SummaryPage />);
    expect(await screen.findByText(i18n.t('main.8-1.call.note'))).toBeInTheDocument();
  });

  it("names the insider's result under the calls (V-40)", async () => {
    open(<SummaryPage />);
    expect(
      await screen.findByText(i18n.t('main.8-1.insider.PARTLY_STOPPED', { n: '2', count: 2 })),
    ).toBeInTheDocument();
  });

  // 구현계획 NW-11: the wrap-up has no lane of its own to go back in; it leads back to the next-chooser the visitor came from.
  it("leads back to the next-chooser of the track the visitor was on, the agent's or the person's", async () => {
    rememberTrack('A');
    const agent = open(<SummaryPage />);
    expect(await screen.findByRole('link', { name: i18n.t('frame.back') })).toHaveAttribute('href', '/agent/next');
    agent.unmount();
    rememberTrack('H');
    open(<SummaryPage />);
    expect(await screen.findByRole('link', { name: i18n.t('frame.back') })).toHaveAttribute('href', '/person/next');
  });

  it('leads back to the start when the visitor stood on no track', async () => {
    open(<SummaryPage />);
    expect(await screen.findByRole('link', { name: i18n.t('frame.back') })).toHaveAttribute('href', '/');
  });

  it('names the screen to go back to by its name, never by its number', async () => {
    open(<SummaryPage />);
    const back = await screen.findAllByRole('link', { name: /다시 보기$/ });
    expect(back.map((link) => link.textContent)).toEqual([
      i18n.t('main.8-1.back', { screen: i18n.t('main.2-2.name') }),
      i18n.t('main.8-1.back', { screen: i18n.t('main.7-3.name') }),
      i18n.t('main.8-1.back', { screen: i18n.t('main.3-1.name') }),
    ]);
    expect(back.every((link) => !/\d-\d/.test(link.textContent ?? ''))).toBe(true);
  });

  // 구현계획 NW-11: a visitor who tried only the agent's track still sees what Contexa let out of the agent's requests.
  describe("a visitor who tried only the agent's track", () => {
    const AGENT_RUN = {
      ...run('T5', 'BLOCK', 0, { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'STOPPED' }),
      runId: 'run-t5',
    };

    it("fills the first card from the agent's own run and leads back to the agent's console", async () => {
      visitorRuns = [AGENT_RUN];
      open(<SummaryPage />);
      expect(await screen.findByText(i18n.t('main.8-1.request.agentLine'))).toBeInTheDocument();
      expect(screen.queryByText(i18n.t('main.8-1.request.none'))).toBeNull();
      expect(screen.getByText(i18n.t('main.8-1.request.title'))).toBeInTheDocument();
      const back = screen.getAllByRole('link', { name: /다시 보기$/ })[0];
      expect(back).toHaveAttribute('href', '/agent/console');
      expect(back).toHaveTextContent(i18n.t('main.6-2.name'));
    });

    it('says what the agent let out when data left, in the words of the agent', async () => {
      visitorRuns = [{ ...AGENT_RUN, engineAction: 'ALLOW', exposedItems: 12 }];
      open(<SummaryPage />);
      expect(await screen.findByText(i18n.t('main.8-1.request.agentTitlePlain'))).toBeInTheDocument();
      expect(screen.queryByText(i18n.t('main.8-1.request.titlePlain'))).toBeNull();
    });

    it("counts a threatening case chosen in the agent's chooser, not only the main case", async () => {
      agentCases = [{ key: 'M10A', title: { ko: '회사 기록에 없는 위임' }, classification: 'THREAT', subject: 'AGENT' }];
      visitorRuns = [{ ...AGENT_RUN, scenarioKey: 'M10A', runId: 'run-m10a' }];
      open(<SummaryPage />);
      expect(await screen.findByText(i18n.t('main.8-1.request.agentLine'))).toBeInTheDocument();
    });

    it('leaves the first card empty after a normal work case, which has no attack to count', async () => {
      agentCases = [{ key: 'N1', title: { ko: '주간 보고서' }, classification: 'NORMAL', subject: 'AGENT' }];
      visitorRuns = [{ ...run('N1', 'ALLOW', 12, { A: 'PASSED', B: 'PASSED', C1: 'PASSED', C2: 'PASSED', D: 'PASSED' }), classification: 'NORMAL' }];
      open(<SummaryPage />);
      expect(await screen.findByText(i18n.t('main.8-1.request.none'))).toBeInTheDocument();
      expect(screen.queryByText(i18n.t('main.8-1.request.agentLine'))).toBeNull();
    });
  });

  it("keeps the person's attack for the first card when the visitor tried both tracks", async () => {
    visitorRuns = [
      ...RUNS,
      { ...run('T5', 'BLOCK', 0, { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'STOPPED' }), runId: 'run-t5' },
    ];
    open(<SummaryPage />);
    expect(await screen.findByText(i18n.t('main.8-1.request.line', { legacy: '-' }), { exact: false })).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('main.8-1.request.agentLine'))).toBeNull();
  });
});
