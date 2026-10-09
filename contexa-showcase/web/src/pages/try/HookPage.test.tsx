import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import HookPage from './HookPage';

const layer = (control: string, outcome: string, verdict: string | null, items: number, ms: number) => ({
  control,
  outcome,
  verdict,
  httpStatus: 200,
  ruleId: null,
  reason: null,
  ruleFacts: {},
  evidence: { deliveredItems: items, responseMs: ms, verdict, outcome },
});

function hook(distinguished: boolean) {
  const column = (
    caseKey: string,
    runId: string,
    contexa: ReturnType<typeof layer>,
    c2: string,
    check: number,
    correct: Record<string, boolean>,
  ) => ({
    caseKey,
    runId,
    startedAt: '2026-10-07T21:31:53Z',
    result: {
      companyTime: '2026-09-30T03:17:00Z',
      layers: [
        layer('A', 'DELIVERED', null, 4831, 67),
        layer('B', 'DELIVERED', null, 4831, 40),
        layer('C1', 'STOPPED', null, 0, 12),
        layer('C2', c2, null, c2 === 'DELIVERED' ? 4831 : 0, 23),
        contexa,
      ],
    },
    business: null,
    correct,
    check: null,
    measurement: {
      protocolId: 'protocol-1',
      runs: 3,
      sameResult: 3 - check,
      passedAfterCheck: check,
      results: {},
    },
  });
  return {
    attacker: column('A3', 'run-a', layer('D', 'HELD', 'CHALLENGE', 0, 6768), 'STOPPED', 0, {
      A: false,
      B: false,
      C1: true,
      C2: true,
      D: true,
    }),
    owner: column('A3T', 'run-b', layer('D', 'DELIVERED', 'ALLOW', 4831, 7337), 'DELIVERED', 1, {
      A: true,
      B: true,
      C1: false,
      C2: true,
      D: true,
    }),
    distinguished,
    textsKeptUntil: null,
  };
}

let current: unknown;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })),
  );
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/hook': current,
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 1, step: 'hook', differences: [] },
          runs: [],
          predictions: [],
        },
        '/api/teasers': { computedAt: '2026-10-08T00:00:00Z', teasers: [] },
        '/api/lab/options': {
          employees: [],
          timeSlots: [{ slot: 'DAWN', representativeTime: '03:17' }],
          items: [],
          operations: [],
          cases: [{ key: 'A3', conditions: { timeSlot: 'DAWN' }, requests: [{ items: 4831 }] }],
          calls: [],
          assessmentReasons: [],
        },
      };
      const body = bodies[url];
      return Promise.resolve(
        new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 }),
      );
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderHook() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <HookPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The first screen (hook): the recorded answers of both runs, and the question only when the record makes it true. */
describe('hook', () => {
  it('replays the recorded answers and asks the question the measurement makes true', async () => {
    current = hook(true);
    renderHook();
    const attacker = await screen.findByRole('region', { name: '계정을 훔친 사람' });
    expect(within(attacker).getByText('본인 확인 · 0건')).toBeInTheDocument();
    expect(within(attacker).getByText('3회 측정 모두 같은 결과')).toBeInTheDocument();
    const owner = screen.getByRole('region', { name: '진짜 직원 · 회사 승인 있음' });
    expect(within(owner).getByText('통과 · 4,831건')).toBeInTheDocument();
    expect(within(owner).getByText('막음 · 업무 중단')).toBeInTheDocument();
    expect(within(owner).getByText('3회 중 1회는 확인 뒤 통과')).toBeInTheDocument();
    // Right and wrong are the server's scores, as a word next to the icon: the gate and the rules against Contexa.
    expect(within(attacker).getAllByText('틀림')).toHaveLength(1);
    expect(within(attacker).getAllByText('맞음')).toHaveLength(3);
    expect(within(owner).getAllByText('틀림')).toHaveLength(1);
    expect(within(attacker).getByText('막아야 정답')).toBeInTheDocument();
    expect(within(owner).getByText('통과가 정답')).toBeInTheDocument();
    expect(screen.getByText('새벽 03:17, 담당이 아닌 프로젝트의 설계 자료 4,831건 반출')).toBeInTheDocument();
    expect(
      screen.getByText('미리 써 둔 규칙 없이 둘을 구별했습니다. Contexa는 어떻게 알았을까요?'),
    ).toBeInTheDocument();
  });

  it('asks the fallback question when the measurement did not tell the two apart', async () => {
    current = hook(false);
    renderHook();
    expect(
      await screen.findByText('같은 요청에 Contexa는 두 사람을 이렇게 판정했습니다. 왜 그랬을까요?'),
    ).toBeInTheDocument();
    expect(screen.queryByText(/미리 써 둔 규칙 없이 둘을 구별했습니다/)).not.toBeInTheDocument();
  });
});
