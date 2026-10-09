import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../i18n';
import i18n from '../i18n';
import { replayFixture } from '../test/replayFixture';
import { required } from '../test/required';
import type { StatsView } from '../api/types';
import ReplayPage from './ReplayPage';
import AdoptPage from './AdoptPage';
import EndPage from './EndPage';
import PolicyPage from './PolicyPage';

const spec = {
  specHash: 'a'.repeat(64),
  spec: {
    codeCommit: 'c',
    engineVersion: '0.1.0',
    effectiveMode: 'ENFORCE',
    chatModel: 'gpt-5-nano',
    embeddingModel: 'text-embedding-3-small',
    embeddingDimensions: 1024,
    promptHash: 'p',
    templateId: null,
    ruleVersion: 'r',
    contractVersion: null,
    timeZone: 'UTC',
  },
};

type Handler = (init?: RequestInit) => { status: number; body: unknown };

let routes: Record<string, Handler>;
const calls: { url: string; init: RequestInit | undefined }[] = [];

beforeEach(() => {
  calls.length = 0;
  routes = {
    'GET /api/pairs': () => ({
      status: 200,
      body: [{ key: 'A3', order: 3, question: replayFixture.question, recorded: true }],
    }),
    'GET /api/visitor': () => ({ status: 200, body: { predictions: {} } }),
    'POST /api/predictions': () => ({
      status: 201,
      body: { scene: 'A3:ATTACK', choice: 'BLOCK', recorded: true, tally: { ALLOW: 0, BLOCK: 1 } },
    }),
    'GET /api/replays/A3': () => ({ status: 200, body: replayFixture }),
    [`GET /api/specs/${'a'.repeat(64)}`]: () => ({ status: 200, body: spec }),
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      const handler = routes[`${init?.method ?? 'GET'} ${url}`];
      const { status, body } = handler ? handler(init) : { status: 404, body: null };
      return new Response(body === null ? null : JSON.stringify(body), { status });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function Where() {
  const location = useLocation();
  return <p data-testid="where">{`${location.pathname} ${JSON.stringify(location.state)}`}</p>;
}

function renderAt(path: string, element: ReactNode, state?: unknown) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[{ pathname: path, state }]}>
        <Routes>
          <Route path="/" element={element} />
          <Route path="/replay/:pairKey" element={path === '/' ? <Where /> : element} />
          <Route path="/end/:pairKey" element={element} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** A stored run's score as the portal returns it, with the parts the record page reads. */
function score(runId: string, title: string, classification: 'THREAT' | 'NORMAL', steps = 1) {
  return {
    runId,
    scenarioKey: 'X',
    scenarioVersion: 1,
    status: 'COMPLETED',
    truthSource: 'RUN_SNAPSHOT',
    truth: { classification, allowedEngineActions: [] },
    definedSteps: steps,
    executedSteps: steps,
    business: {
      D: { result: classification === 'THREAT' ? 'MISSED' : 'PASSED', exposedItems: 0, worstStep: 1 },
    },
    correct: { A: false, D: classification !== 'THREAT' },
    rightControls: 1,
    verdicts: [],
    checks: [],
    title: { ko: title, en: title },
  };
}

describe('the stored real record (D-35)', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'matchMedia',
      vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })),
    );
    routes['GET /api/runs/run-0000000000a1/score'] = () => ({
      status: 200,
      body: score('run-0000000000a1', 'Insider bulk export', 'THREAT'),
    });
    routes['GET /api/runs/run-0000000000b2/score'] = () => ({
      status: 200,
      body: score('run-0000000000b2', 'Approved project transfer', 'NORMAL'),
    });
  });

  it("replays a recorded pair's runs as the first screen does, each run's answers as recorded", async () => {
    await i18n.changeLanguage('en');
    renderAt('/replay/A3', <ReplayPage />);

    expect(await screen.findByRole('heading', { name: 'Insider bulk export' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Approved project transfer' })).toBeInTheDocument();
    expect(screen.getAllByText('Same result in all 5 runs')).toHaveLength(2);
    const attack = required(
      screen.getByRole('heading', { name: 'Insider bulk export' }).closest('section'),
    ) as HTMLElement;
    expect(within(attack).getByText('Right answer: stop it')).toBeInTheDocument();
    // Contexa's recorded answer of the attack run: it let 4,831 items out.
    expect(within(attack).getByText('Passed · 4,831 records')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Decision details · Insider bulk export' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'To the first screen' })).toHaveAttribute('href', '/');
  });

  it("replays a case without a recording from its current measurement's middle run, and leads back", async () => {
    await i18n.changeLanguage('en');
    routes['GET /api/replays/A6T'] = () => ({ status: 404, body: null });
    routes['GET /api/cases/A6T/measured'] = () => ({
      status: 200,
      body: {
        caseKey: 'A6T',
        settingHash: 's',
        protocolId: 'protocol-1',
        runs: 3,
        results: { PASSED: 2, PASSED_AFTER_CHECK: 1 },
        allSame: false,
        analysisMs: null,
        exposedItems: null,
        list: [],
        resumed: null,
        responseMs: null,
        middleRun: 'run-0000000000b2',
      },
    });
    routes['GET /api/runs/run-0000000000b2/steps/1/result'] = () => ({
      status: 200,
      body: {
        companyTime: '2026-09-30T03:17:00Z',
        layers: required(replayFixture.scenes[1]).layers,
        engineReason: null,
        companyFacts: [],
        tally: { stopped: 0, passed: 5, other: 0 },
        existingTally: { stopped: 0, passed: 4, other: 0 },
      },
    });
    routes['GET /api/runs/run-0000000000b2/score'] = () => ({
      status: 200,
      body: score('run-0000000000b2', 'Approved project transfer', 'NORMAL', 5),
    });
    renderAt('/replay/A6T', <ReplayPage />);

    expect(await screen.findByRole('heading', { name: 'Approved project transfer' })).toBeInTheDocument();
    expect(screen.getByText('Passed after a check in 1 of 3 runs')).toBeInTheDocument();
    expect(screen.getByText(/This case has 5 requests/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Decision details' })).toBeInTheDocument();
  });

  it('says the record is being prepared when the case has neither a recording nor a measurement', async () => {
    await i18n.changeLanguage('en');
    routes['GET /api/replays/A3'] = () => ({ status: 404, body: null });
    routes['GET /api/cases/A3/measured'] = () => ({ status: 404, body: null });
    renderAt('/replay/A3', <ReplayPage />);
    expect(await screen.findByText('The real run of this scene is being prepared')).toBeInTheDocument();
  });
});

const statsView: StatsView = {
  computedAt: '2026-10-05T07:30:12.000Z',
  runs: { completed: 1284, failed: 3, today: 41, live: 334, firstAt: '2026-10-04T06:00:00Z', lastAt: null },
  decisionTime: { decisions: 760, p50Ms: 2500, p95Ms: 3850 },
  engineActions: { ALLOW: 728, CHALLENGE: 1, BLOCK: 31, ESCALATE: 0 },
  engineDecisions: 760,
  unresolved: { technical: 87, noNewAnalysis: 29 },
  agreement: {
    agreeing: 9,
    repetitions: 10,
    recordings: [
      { pairKey: 'A3', scene: 'ATTACK', agreeing: 4, repetitions: 5, recordedAt: '2026-10-05T01:00:00Z' },
      { pairKey: 'A3', scene: 'LEGITIMATE', agreeing: 5, repetitions: 5, recordedAt: '2026-10-05T01:00:00Z' },
    ],
  },
  scope: { threatRuns: 3, normalRuns: 1, otherRuns: 192 },
  layers: [
    {
      control: 'A',
      threat: { runs: 3, stopped: 1, partlyStopped: 0, missed: 2, unresolved: 0, exposedItems: 0 },
      normal: { runs: 1, passed: 1, passedAfterCheck: 0, halted: 0, unresolved: 0 },
    },
    {
      control: 'B',
      threat: { runs: 3, stopped: 0, partlyStopped: 0, missed: 3, unresolved: 0, exposedItems: 0 },
      normal: { runs: 1, passed: 1, passedAfterCheck: 0, halted: 0, unresolved: 0 },
    },
    {
      control: 'C1',
      threat: { runs: 3, stopped: 2, partlyStopped: 0, missed: 1, unresolved: 0, exposedItems: 0 },
      normal: { runs: 1, passed: 0, passedAfterCheck: 0, halted: 1, unresolved: 0 },
    },
    {
      control: 'C2',
      threat: { runs: 3, stopped: 2, partlyStopped: 0, missed: 0, unresolved: 1, exposedItems: 0 },
      normal: { runs: 1, passed: 1, passedAfterCheck: 0, halted: 0, unresolved: 0 },
    },
    {
      control: 'D',
      threat: { runs: 3, stopped: 1, partlyStopped: 0, missed: 2, unresolved: 0, exposedItems: 0 },
      normal: { runs: 1, passed: 0, passedAfterCheck: 1, halted: 0, unresolved: 0 },
    },
  ],
  spec: {
    specHash: 'a'.repeat(64),
    codeCommit: 'f1f5c2a4',
    engineVersion: '0.1.0',
    effectiveMode: 'ENFORCE',
    chatModel: 'gpt-5-nano',
    embeddingModel: 'text-embedding-3-small',
    timeZone: 'UTC',
  },
  specCount: 2,
  releases: 0,
};

const halfResult = {
  pairKey: 'A3',
  scenes: [
    {
      kind: 'ATTACK',
      choice: 'BLOCK',
      carriedOver: false,
      myCorrect: true,
      contexaOutcome: 'DELIVERED',
      contexaVerdict: 'ALLOW',
      contexaResult: 'MISSED',
      contexaExposed: 4831,
      contexaCorrect: false,
      truth: required(replayFixture.scenes[0]).truth,
      scenarioKey: 'A3',
      resumedMillis: null as number | null,
    },
    {
      kind: 'LEGITIMATE',
      choice: 'BLOCK',
      carriedOver: true,
      myCorrect: false,
      contexaOutcome: 'DELIVERED',
      contexaVerdict: 'ALLOW',
      contexaResult: 'PASSED',
      contexaExposed: 4831,
      contexaCorrect: true,
      truth: required(replayFixture.scenes[1]).truth,
      scenarioKey: 'A3T',
      resumedMillis: null as number | null,
    },
  ],
  mine: { hits: 1, total: 2 },
  contexa: { hits: 1, total: 2 },
};

describe('end screen', () => {
  it('shows the server result, claims only what the recording supports, and makes the share card', async () => {
    await i18n.changeLanguage('en');
    routes['GET /api/results/A3'] = () => ({ status: 200, body: halfResult });
    routes['POST /api/shares'] = () => ({
      status: 201,
      body: {
        shareKey: 'AbCdEfGh23',
        url: 'https://demo.example/s/AbCdEfGh23',
        image: '/s/AbCdEfGh23/card.png',
      },
    });
    renderAt('/end/A3', <EndPage />);

    expect(await screen.findByText('Your result · 2 scenes · real recorded runs')).toBeInTheDocument();
    expect(screen.getAllByText('1/2')).toHaveLength(2);
    expect(
      screen.getByText('Your answer to the first question was applied to both requests of the pair.'),
    ).toBeInTheDocument();
    expect(screen.getByText('In this recording Contexa got 1 of 2 scenes right')).toBeInTheDocument();
    expect(screen.queryByText('Stops only what it should · the legitimate request passes')).toBeNull();
    expect(screen.getAllByText('Right')).toHaveLength(2);
    expect(screen.getAllByText('Wrong')).toHaveLength(2);
    expect(screen.getByRole('link', { name: /Change the conditions and try it/ })).toHaveAttribute(
      'href',
      '/',
    );
    expect(within(screen.getByRole('main')).getByRole('link', { name: 'Benchmark' })).toHaveAttribute(
      'href',
      '/benchmark',
    );
    // F-13: each scene states the ground truth its run recorded, never a sentence fixed by the scene's kind.
    expect(screen.getByText('Ground truth: Attack')).toBeInTheDocument();
    expect(screen.getByText('Ground truth: Normal work')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Share the result' }));
    const posted = calls.find((call) => call.url === '/api/shares');
    expect(posted?.init?.body).toBe(JSON.stringify({ pairKey: 'A3', language: 'en' }));
    expect(
      await screen.findByRole('img', { name: 'Share card: Your call 1/2 · Contexa 1/2' }),
    ).toHaveAttribute('src', '/s/AbCdEfGh23/card.png');
    expect(screen.getByLabelText('Share link')).toHaveValue('https://demo.example/s/AbCdEfGh23');
  });

  it('marks the precise claim only when Contexa got every scene right, and says when nobody voted', async () => {
    await i18n.changeLanguage('ko');
    routes['GET /api/results/A3'] = () => ({
      status: 200,
      body: {
        ...halfResult,
        scenes: halfResult.scenes.map((scene) => ({
          ...scene,
          choice: null,
          carriedOver: false,
          myCorrect: null,
        })),
        mine: null,
        contexa: { hits: 2, total: 2 },
      },
    });
    renderAt('/end/A3', <EndPage />);

    expect(await screen.findByText('2/2')).toBeInTheDocument();
    expect(screen.queryByText('내 판단 · 맞힌 장면')).toBeNull();
    expect(screen.getByText('막을 것만 막는다 · 정당한 요청은 통과')).toBeInTheDocument();
    expect(screen.queryByText('첫 질문의 판단을 짝을 이룬 두 요청 모두에 적용했습니다.')).toBeNull();
  });

  it('claims the recovery only where the recording has it, with its recorded time (H-09 #29)', async () => {
    await i18n.changeLanguage('en');
    routes['GET /api/results/A3'] = () => ({ status: 200, body: halfResult });
    renderAt('/end/A3', <EndPage />);
    expect(await screen.findByText('In this recording Contexa got 1 of 2 scenes right')).toBeInTheDocument();
    expect(screen.queryByText(/work went through/)).toBeNull();
    cleanup();

    const resumed = {
      ...halfResult,
      scenes: halfResult.scenes.map((scene, index) =>
        index === 1 ? { ...scene, resumedMillis: 4200 } : scene,
      ),
    };
    routes['GET /api/results/A3'] = () => ({ status: 200, body: resumed });
    renderAt('/end/A3', <EndPage />);
    expect(
      await screen.findByText('Does not stop at blocking · work went through 4.2 s after the check'),
    ).toBeInTheDocument();
  });

  it("states what the two requests share and where they differ, from the cases' definitions (H-09 #28)", async () => {
    await i18n.changeLanguage('en');
    const conditions = {
      employee: 'adm-a',
      timeSlot: 'DAWN',
      place: 'OFFICE',
      device: 'USUAL',
      operation: 'EXPORT',
      target: 'UNASSIGNED',
      items: 4831,
      approval: false,
      ticket: 'NONE',
      claim: 'NONE',
      onCall: false,
    };
    routes['GET /api/results/A3'] = () => ({ status: 200, body: halfResult });
    routes['GET /api/lab/options'] = () => ({
      status: 200,
      body: {
        employees: [],
        timeSlots: [],
        items: [],
        operations: [],
        calls: [],
        assessmentReasons: [],
        cases: [
          { key: 'A3', conditions, facts: [], requests: [] },
          { key: 'A3T', conditions: { ...conditions, approval: true }, facts: [], requests: [] },
        ],
      },
    });
    renderAt('/end/A3', <EndPage />);
    expect(
      await screen.findByText(
        'Same in both requests: Employee, Time, Place, Device, Work, Target, Items, Ticket record, Ticket named in the request, On call. Different: Approval record. Only the company records differ, so the requests alone cannot tell the two apart.',
      ),
    ).toBeInTheDocument();
    // Only here, where the company records alone differ, does the title say the two requests look the same.
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Two requests that look the same. Who told them apart?',
      }),
    ).toBeInTheDocument();
  });

  it('says the result is being prepared when the pair is not published', async () => {
    await i18n.changeLanguage('en');
    renderAt('/end/A3', <EndPage />);
    expect(await screen.findByText('The real run of this scene is being prepared')).toBeInTheDocument();
  });
});

describe('privacy notice', () => {
  it('says what is not collected and names the only cookies, with no choice to make', async () => {
    await i18n.changeLanguage('en');
    renderAt('/', <PolicyPage />);

    expect(screen.getByRole('heading', { level: 1, name: 'Privacy notice' })).toBeInTheDocument();
    expect(screen.getByRole('rowheader', { name: 'SC_VISITOR' })).toBeInTheDocument();
    expect(screen.getByRole('rowheader', { name: 'XSRF-TOKEN' })).toBeInTheDocument();
    expect(within(screen.getByRole('main')).queryByRole('button')).toBeNull();
  });
});

describe('adopting Contexa', () => {
  it('shows the real coordinates and the Shadow numbers counted from this demo', async () => {
    await i18n.changeLanguage('en');
    routes['GET /api/stats'] = () => ({ status: 200, body: statsView });
    renderAt('/', <AdoptPage />);

    expect(
      screen.getByRole('heading', { level: 1, name: 'Adopt Contexa: attach, watch, enforce' }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText('Attach')).toHaveTextContent(
      'implementation "ai.ctxa:spring-boot-starter-contexa:0.1.0"',
    );
    expect(screen.getByLabelText('Attach')).toHaveTextContent('@EnableAISecurity');
    expect(screen.getByLabelText('Watch')).toHaveTextContent('mode: SHADOW');
    expect(screen.getByLabelText('Enforce')).toHaveTextContent('mode: ENFORCE');
    // The sentence carries the source tag of the engine's records beside it.
    expect(
      await screen.findByText(
        /Counted from this demo’s 760 real engine decisions\. In Shadow mode they would only have been recorded, not enforced\./,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText('Would have been blocked').nextSibling).toHaveTextContent('31');
  });
});
