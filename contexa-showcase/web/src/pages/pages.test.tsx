import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../i18n';
import i18n from '../i18n';
import { replayFixture } from '../test/replayFixture';
import { required } from '../test/required';
import type { StatsView } from '../api/types';
import HomePage from './HomePage';
import ReplayPage from './ReplayPage';
import StatsPage from './StatsPage';
import ExplorePage from './ExplorePage';
import TryPage from './TryPage';

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
      return new Response(body === null ? '' : JSON.stringify(body), { status });
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
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('first screen', () => {
  it('asks the recorded question and turns the first button into the stored vote', async () => {
    await i18n.changeLanguage('en');
    renderAt('/', <HomePage />);

    expect(await screen.findByRole('heading', { name: replayFixture.question.en })).toBeInTheDocument();
    expect(screen.getByText('What would you do?')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Skip and see the result/ })).toHaveAttribute(
      'href',
      '/replay/A3',
    );

    await userEvent.click(await screen.findByRole('button', { name: 'Block it' }));

    const post = calls.find((call) => call.init?.method === 'POST');
    expect(JSON.parse(String(post?.init?.body))).toEqual({ scene: 'A3:ATTACK', choice: 'BLOCK' });
    expect(await screen.findByTestId('where')).toHaveTextContent('/replay/A3 {"choice":"BLOCK"}');
  });

  it('says the run is being prepared when no pair is recorded', async () => {
    await i18n.changeLanguage('en');
    routes['GET /api/pairs'] = () => ({ status: 200, body: [] });
    renderAt('/', <HomePage />);
    expect(await screen.findByText('The real run of this scene is being prepared')).toBeInTheDocument();
  });
});

describe('verdict comparison', () => {
  it('shows exactly the recorded outcome and verdict of every layer, then the legitimate request', async () => {
    await i18n.changeLanguage('en');
    renderAt('/replay/A3', <ReplayPage />, { choice: 'BLOCK' });

    const attack = required(replayFixture.scenes[0], 'attack scene');
    expect(await screen.findByRole('heading', { name: attack.sentence.en })).toBeInTheDocument();
    expect(screen.getByText('Same result in 5 of 5 runs')).toBeInTheDocument();
    expect(screen.getByText('Your call: Block · Contexa: Data delivered')).toBeInTheDocument();

    for (const scene of replayFixture.scenes) {
      if (scene.kind === 'LEGITIMATE') {
        await userEvent.click(screen.getByRole('button', { name: 'Next' }));
        expect(await screen.findByRole('heading', { name: scene.sentence.en })).toBeInTheDocument();
      }
      for (const layer of scene.layers) {
        const card = document.querySelector(`article[data-control="${layer.control}"]`) as HTMLElement;
        const outcome = layer.outcome === 'DELIVERED' ? 'Data delivered' : 'Data stopped';
        expect(within(card).getByText(outcome), `${scene.kind} ${layer.control}`).toBeInTheDocument();
      }
    }
    expect(screen.getByText('You have seen both requests')).toBeInTheDocument();
  });

  it('opens the evidence chain of Contexa with the decision ID and the engine text', async () => {
    await i18n.changeLanguage('en');
    renderAt('/replay/A3', <ReplayPage />);

    const card = required(
      (await screen.findAllByRole('article')).find((article) => article.dataset.control === 'D'),
    );
    expect(within(card).getByText('Permitted · short usual pattern · no concrete risk')).toBeInTheDocument();
    await userEvent.click(within(card).getByRole('button', { name: /Evidence chain/ }));

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('3522bb83-0f99-481d-9466-f1249f5094df')).toBeInTheDocument();
    expect(within(dialog).getByText('Applied before the response')).toBeInTheDocument();
    const reasoning = required(required(replayFixture.scenes[0]).engineReason?.reasoning, 'engine reasoning');
    expect(within(dialog).getByText(reasoning)).toBeInTheDocument();
    expect(within(dialog).getByText('Analysis timeline')).toBeInTheDocument();
    expect(
      within(dialog)
        .getAllByTestId('timeline-offset')
        .map((offset) => offset.textContent),
    ).toEqual(['+38 ms', '+38 ms', '+1,666 ms', '+1,666 ms', '+1,702 ms']);
    expect(
      within(dialog).getByText('The decision took effect 36 ms before the response.'),
    ).toBeInTheDocument();
  });

  it('says the run is being prepared when the pair has no published recording', async () => {
    await i18n.changeLanguage('en');
    routes['GET /api/replays/A3'] = () => ({ status: 404, body: null });
    renderAt('/replay/A3', <ReplayPage />);
    expect(await screen.findByText('The real run of this scene is being prepared')).toBeInTheDocument();
  });
});

describe('try it yourself', () => {
  const layers = {
    A: { outcome: 'DELIVERED', httpStatus: 200 },
    B: { outcome: 'DELIVERED', httpStatus: 200 },
    C1: { outcome: 'DELIVERED', httpStatus: 200 },
    C2: { outcome: 'DELIVERED', httpStatus: 200 },
    D: { outcome: 'HELD', httpStatus: 401 },
  };
  const challenge = {
    stage: 'WAITING',
    code: null,
    secondsLeft: 120,
    attempts: 0,
    error: null,
    cause: null,
    codeRequestedMs: null,
    verifiedMs: null,
    reissueSentMs: null,
    reissueDoneMs: null,
    reissueStatus: null,
    reissueOutcome: null,
  };
  function view(overrides: Record<string, unknown>, challengeOverrides: Record<string, unknown> | null) {
    return {
      liveRunId: 'live-1',
      scenario: 'K2',
      status: 'CHALLENGE',
      runId: 'run-1',
      steps: [{ stepNo: 1, operation: 'DOCUMENT_READ', layers }],
      challenge: challengeOverrides === null ? null : { ...challenge, ...challengeOverrides },
      failure: null,
      ...overrides,
    };
  }

  beforeEach(() => {
    routes['GET /api/live/config'] = () => ({
      status: 200,
      body: {
        scenarios: [
          {
            key: 'K2',
            title: { ko: '담당 도면 열람', en: 'Opening an assigned drawing' },
            classification: 'NORMAL',
          },
        ],
      },
    });
  });

  it('says it is being prepared when the portal has no live space', async () => {
    await i18n.changeLanguage('en');
    delete routes['GET /api/live/config'];
    renderAt('/', <TryPage />);
    expect(await screen.findByText('The real run of this scene is being prepared')).toBeInTheDocument();
  });

  it('runs live, answers the check with the demo inbox code and shows the work coming back', async () => {
    await i18n.changeLanguage('en');
    let current = view({}, {});
    routes['POST /api/live/runs'] = () => ({ status: 202, body: current });
    routes['POST /api/live/runs/current/code'] = () => {
      current = view({}, { stage: 'CODE_SHOWN', code: '481516', codeRequestedMs: 120 });
      return { status: 200, body: current };
    };
    routes['POST /api/live/runs/current/answer'] = () => {
      current = view(
        { status: 'COMPLETED' },
        {
          stage: 'DONE',
          codeRequestedMs: 120,
          verifiedMs: 6400,
          reissueSentMs: 6450,
          reissueDoneMs: 6480,
          reissueStatus: 200,
          reissueOutcome: 'DELIVERED',
          secondsLeft: 0,
        },
      );
      return { status: 200, body: current };
    };
    routes['GET /api/live/runs/current'] = () => ({ status: 404, body: null });
    renderAt('/', <TryPage />);

    await userEvent.click(await screen.findByRole('button', { name: 'Run' }));
    routes['GET /api/live/runs/current'] = () => ({ status: 200, body: current });
    expect(await screen.findByText('Contexa asks you to confirm it is you')).toBeInTheDocument();
    expect(screen.getByText('Delivery on hold')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Send me the code' }));
    expect(await screen.findByTestId('inbox-code')).toHaveTextContent('481516');
    expect(screen.getByText("In a real deployment this goes to the employee's mailbox.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Confirm with this code' }));

    expect(await screen.findByText('Control and recovery')).toBeInTheDocument();
    expect(screen.getByText('Original request sent again +6,450 ms')).toBeInTheDocument();
    expect(screen.getByText('t+6,480 ms')).toBeInTheDocument();
    expect(screen.getByText('Data delivered · HTTP 200')).toBeInTheDocument();
    expect(screen.getByText('You confirmed it was you and the work carried on')).toBeInTheDocument();
    const answer = calls.find((call) => call.url === '/api/live/runs/current/answer');
    expect(answer?.init?.body).toBe(JSON.stringify({ code: '481516' }));
  });

  it('tells a second visitor that live runs are pausing', async () => {
    await i18n.changeLanguage('ko');
    routes['GET /api/live/runs/current'] = () => ({ status: 404, body: null });
    routes['POST /api/live/runs'] = () => ({ status: 409, body: null });
    renderAt('/', <TryPage />);
    await userEvent.click(await screen.findByRole('button', { name: '실행' }));
    expect(await screen.findByText('실시간 실행이 잠시 쉬고 있습니다.')).toBeInTheDocument();
  });
});

describe('explore conditions', () => {
  const slots = ['DAWN', 'MORNING', 'AFTERNOON', 'EVENING'];
  const items = [40, 480, 4831, 6200];
  const recordedKey = 'adm-a.DAWN.4831.NONE.USUAL';
  const attack = required(replayFixture.scenes[0], 'attack scene');

  beforeEach(() => {
    routes['GET /api/live/config'] = () => ({
      status: 200,
      body: { scenarios: [], turnstileSiteKey: null, dailyRuns: 10, remainingToday: 10, paused: false },
    });
    routes['GET /api/live/runs/current'] = () => ({ status: 404, body: null });
    routes['GET /api/combinations?employee=adm-a&ticket=NONE&device=USUAL'] = () => ({
      status: 200,
      body: {
        catalogVersion: 1,
        employees: ['adm-a', 'eng-k'],
        items,
        cells: items.flatMap((count) =>
          slots.map((slot) => {
            const key = `adm-a.${slot}.${count}.NONE.USUAL`;
            const recorded = key === recordedKey;
            return {
              key,
              slot,
              items: count,
              recorded,
              recordedAt: recorded ? '2026-10-05T06:30:00Z' : null,
              engineVerdict: recorded ? 'BLOCK' : null,
              engineOutcome: recorded ? 'STOPPED' : null,
            };
          }),
        ),
      },
    });
    routes[`GET /api/combinations/${recordedKey}`] = () => ({
      status: 200,
      body: {
        key: recordedKey,
        employee: 'adm-a',
        slot: 'DAWN',
        items: 4831,
        ticket: 'NONE',
        device: 'USUAL',
        recorded: true,
        recordedAt: '2026-10-05T06:30:00Z',
        runId: 'run-1',
        result: {
          companyTime: '2026-09-30T03:17:00Z',
          layers: attack.layers,
          engineReason: attack.engineReason,
          companyFacts: attack.companyFacts,
        },
      },
    });
    routes['GET /api/combinations/adm-a.MORNING.40.NONE.USUAL'] = () => ({
      status: 200,
      body: {
        key: 'adm-a.MORNING.40.NONE.USUAL',
        employee: 'adm-a',
        slot: 'MORNING',
        items: 40,
        ticket: 'NONE',
        device: 'USUAL',
        recorded: false,
        recordedAt: null,
        runId: null,
        result: null,
      },
    });
  });

  it('shows the stored real run of the chosen cell with its time, and the map filled only by real runs', async () => {
    await i18n.changeLanguage('en');
    renderAt('/', <ExplorePage />);

    expect(await screen.findByText(/Real run record · .*UTC/)).toBeInTheDocument();
    const cell = screen.getByRole('button', { name: 'Dawn · 5,000 or fewer · Blocked' });
    expect(cell).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getAllByRole('button', { name: /· Not run$/ })).toHaveLength(15);
    expect(screen.getByText(/Admin A · Dawn · export 4,831 GB-500 design documents/)).toBeInTheDocument();
  });

  it('runs a new cell live through the gate and tells its place in the queue', async () => {
    await i18n.changeLanguage('en');
    routes['POST /api/live/combinations'] = () => ({
      status: 202,
      body: {
        liveRunId: 'live-1',
        scenario: 'adm-a.MORNING.40.NONE.USUAL',
        status: 'QUEUED',
        queuePosition: 2,
        runId: null,
        steps: [],
        challenge: null,
        failure: null,
      },
    });
    renderAt('/', <ExplorePage />);
    await userEvent.click(await screen.findByRole('button', { name: 'Morning · 50 or fewer · Not run' }));

    expect(await screen.findByText('No one has run this combination yet.')).toBeInTheDocument();
    expect(screen.getByText('Live runs left today: 10/10')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Run this combination' }));

    expect(
      await screen.findByText('Number 2 in line · it starts as soon as it is your turn'),
    ).toBeInTheDocument();
    const posted = calls.find((call) => call.url === '/api/live/combinations');
    expect(posted?.init?.body).toBe(
      JSON.stringify({ key: 'adm-a.MORNING.40.NONE.USUAL', turnstileToken: null }),
    );
  });

  it('shows the daily limit when the gate refuses a new cell', async () => {
    await i18n.changeLanguage('ko');
    routes['POST /api/live/combinations'] = () => ({ status: 429, body: { reason: 'VISITOR_LIMIT' } });
    renderAt('/', <ExplorePage />);
    await userEvent.click(await screen.findByRole('button', { name: '아침 · 50 이하 · 미실행' }));
    await userEvent.click(await screen.findByRole('button', { name: '이 조합 실행' }));

    expect(await screen.findByText('오늘의 실시간 실행을 모두 썼습니다.')).toBeInTheDocument();
  });
});

const statsView: StatsView = {
  computedAt: '2026-10-05T07:30:12.000Z',
  runs: { completed: 1284, failed: 3, today: 41, live: 334, firstAt: '2026-10-04T06:00:00Z', lastAt: null },
  decisionTime: { decisions: 760, p50Ms: 2500, p95Ms: 3850 },
  engineActions: { ALLOW: 728, CHALLENGE: 1, BLOCK: 31, ESCALATE: 0 },
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
      threat: { runs: 3, leaked: 2, stopped: 1, unresolved: 0 },
      normal: { runs: 1, passed: 1, challenged: 0, blocked: 0, unresolved: 0 },
    },
    {
      control: 'B',
      threat: { runs: 3, leaked: 3, stopped: 0, unresolved: 0 },
      normal: { runs: 1, passed: 1, challenged: 0, blocked: 0, unresolved: 0 },
    },
    {
      control: 'C1',
      threat: { runs: 3, leaked: 1, stopped: 2, unresolved: 0 },
      normal: { runs: 1, passed: 0, challenged: 0, blocked: 1, unresolved: 0 },
    },
    {
      control: 'C2',
      threat: { runs: 3, leaked: 0, stopped: 2, unresolved: 1 },
      normal: { runs: 1, passed: 1, challenged: 0, blocked: 0, unresolved: 0 },
    },
    {
      control: 'D',
      threat: { runs: 3, leaked: 2, stopped: 1, unresolved: 0 },
      normal: { runs: 1, passed: 0, challenged: 1, blocked: 0, unresolved: 0 },
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
};

describe('execution statistics', () => {
  it('shows exactly the counted numbers, each layer of the table, the decision mix and the specification', async () => {
    await i18n.changeLanguage('en');
    routes['GET /api/stats'] = () => ({ status: 200, body: statsView });
    renderAt('/', <StatsPage />);

    expect(await screen.findByRole('heading', { name: 'Execution statistics' })).toBeInTheDocument();
    expect(screen.getByText('Operations record · not the benchmark')).toBeInTheDocument();
    expect(await screen.findByText('1,284')).toBeInTheDocument();
    expect(screen.getByText('41 today · 334 by visitors')).toBeInTheDocument();
    expect(screen.getByText('2.5 s')).toBeInTheDocument();
    expect(screen.getByText('p95 3.9 s · 760 decisions')).toBeInTheDocument();
    expect(screen.getByText('90%')).toBeInTheDocument();
    expect(screen.getByText('2 published scenes · 9 of 10 runs agree')).toBeInTheDocument();

    const row = (control: string) =>
      within(document.querySelector(`tr[data-control="${control}"]`) as HTMLElement);
    expect(
      row('D')
        .getAllByRole('cell')
        .map((cell) => cell.querySelector('[data-part="value"]')?.textContent),
    ).toEqual(['2/3 (67%)', '1/3 (33%)', '0/1 (0%)', '1/1 (100%)']);
    expect(row('C1').getByRole('rowheader')).toHaveTextContent('Threshold rules');
    expect(
      screen.getByText(/3 attack runs and 1 normal-work runs were counted\. 192 runs/),
    ).toBeInTheDocument();
    expect(screen.getByText('728 · 95.8%')).toBeInTheDocument();
    expect(screen.getByText('0 · 0%')).toBeInTheDocument();
    expect(screen.getByText('gpt-5-nano')).toBeInTheDocument();
    expect(screen.getByText('Updated 2026-10-05 07:30 UTC')).toBeInTheDocument();
  });

  it('says so before the official recordings and when nothing has run', async () => {
    await i18n.changeLanguage('ko');
    routes['GET /api/stats'] = () => ({
      status: 200,
      body: { ...statsView, agreement: { agreeing: 0, repetitions: 0, recordings: [] } },
    });
    const first = renderAt('/', <StatsPage />);
    expect(await screen.findByText('공식 녹화 전')).toBeInTheDocument();
    first.unmount();

    routes['GET /api/stats'] = () => ({
      status: 200,
      body: { ...statsView, runs: { ...statsView.runs, completed: 0 } },
    });
    renderAt('/', <StatsPage />);
    expect(await screen.findByText('아직 집계할 실제 실행이 없습니다')).toBeInTheDocument();
  });
});
