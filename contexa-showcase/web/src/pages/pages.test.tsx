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
import EndPage from './EndPage';

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

// The stored real record, the privacy notice and the adopt space: ReplayPage.test.tsx, PolicyPage.test.tsx and
// AdoptPage.test.tsx (R7, RO-4 to RO-7).

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
    expect(await screen.findByText(i18n.t('state.notReady'))).toBeInTheDocument();
  });
});
