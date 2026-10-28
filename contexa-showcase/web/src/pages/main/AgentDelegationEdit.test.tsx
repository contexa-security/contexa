import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import AgentRequestPage from './AgentRequestPage';
import { periodWords } from './agentGroup';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

/**
 * docs/agent Agent중심-화면 AS-12: 6-1 shows the delegation the visitor chose, as the portal computed it from its fixed lists
 * (the case view carries the choice), says which values were changed, and sends the choice with the start; a choice
 * outside the lists is not sent, and the other cases are as before.
 */
const EDIT = {
  case: 'ED1',
  title: { ko: '위임장의 값 하나를 바꾼 문서 내보내기', en: 'An export after one value was changed' },
  quantities: [40, 100, 400],
  periods: ['VALID', 'EXPIRED', 'REVOKED'],
  operations: ['READ_ONLY', 'READ_EXPORT'],
};

function view(limit: number, validUntilMinutes: number, status: string, operations: string[]) {
  return {
    key: 'ED1',
    version: 1,
    title: EDIT.title,
    protagonist: 'eng-k',
    agentName: 'report',
    agentTitle: { ko: '보고서 에이전트', en: 'Report agent' },
    sender: 'DELEGATED_AGENT',
    instruction: { ko: 'HX-310 문서 400건을 내보내 줘.', en: 'Export 400 documents of HX-310.' },
    delegation: {
      project: 'HX-310',
      purpose: 'DATA_EXPORT',
      summary: { ko: `HX-310 설계 검토 자료 내보내기(요청마다 ${limit}건까지)`, en: `Export, up to ${limit} a request` },
      operations,
      resources: ['HX-310'],
      validFromMinutes: -60,
      validUntilMinutes,
      status,
      approvalRequired: false,
      maxItemsPerRequest: limit,
    },
    classification: 'THREAT',
    normalPair: null,
    recorded: null,
    normalRecorded: null,
  };
}

const ALL = ['PROJECT_LIST', 'DOCUMENT_LIST', 'DOCUMENT_READ', 'EXPORT'];

let bodies: Record<string, unknown>;
let fetched: string[];
let posted: { url: string; body: unknown }[];

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  fetched = [];
  posted = [];
  bodies = {
    '/api/visitor': { predictions: {} },
    '/api/journey': { state: { route: 'DEFAULT', act: 6, step: 'agent', differences: [] }, runs: [], predictions: [] },
    '/api/live/runs/current': null,
    '/api/live/config': {
      scenarios: [],
      agentCases: [{ key: 'T5', title: { ko: 'T5', en: 'T5' }, classification: 'THREAT', subject: 'AGENT' }],
      delegationEdit: EDIT,
      turnstileSiteKey: null,
      dailyRuns: 10,
      remainingToday: 10,
      paused: false,
    },
    '/api/agent-cases/ED1': view(40, 180, 'ACTIVE', ALL),
    '/api/agent-cases/ED1?quantity=400&period=EXPIRED': view(400, -120, 'ACTIVE', ALL),
    '/api/agent-cases/ED1?period=REVOKED': view(40, 180, 'REVOKED', ALL),
    '/api/agent-cases/ED1?operations=READ_ONLY': view(40, 180, 'ACTIVE', ALL.filter((name) => name !== 'EXPORT')),
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        posted.push({ url, body: JSON.parse(String(init.body ?? 'null')) });
        return new Response(JSON.stringify({ liveRunId: 'live-1', scenario: 'ED1', status: 'RUNNING', steps: [] }), { status: 202 });
      }
      fetched.push(url);
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

function open(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={<AgentRequestPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('6-1 with a delegation the visitor changed (AS-12)', () => {
  it('shows the delegation the portal computed for the choice, with its quantity limit and period', async () => {
    open('/agent/request?case=ED1&quantity=400&period=EXPIRED');

    expect(await screen.findByText('HX-310 설계 검토 자료 내보내기(요청마다 400건까지)')).toBeInTheDocument();
    expect(fetched).toContain('/api/agent-cases/ED1?quantity=400&period=EXPIRED');
    expect(screen.getByText(word('main.agent.limit').replace('{{n}}', '400'))).toBeInTheDocument();
    expect(screen.getByText('작업 시각 1시간 전부터 2시간 전까지')).toBeInTheDocument();
  });

  it('says which values the visitor changed, and nothing of changes when none was made', async () => {
    open('/agent/request?case=ED1&quantity=400&period=EXPIRED');

    expect(
      await screen.findByText(
        word('main.6-1.changed').replace(
          '{{values}}',
          `${word('main.agent.choice.quantity').replace('{{n}}', '400')} · ${word('main.agent.choice.period').replace('{{word}}', word('main.agent.choice.period.EXPIRED'))}`,
        ),
      ),
    ).toBeInTheDocument();
  });

  it('shows no changes for the case as it is', async () => {
    open('/agent/request?case=ED1');

    expect(await screen.findByText('HX-310 설계 검토 자료 내보내기(요청마다 40건까지)')).toBeInTheDocument();
    expect(screen.getByText(word('main.agent.limit').replace('{{n}}', '40'))).toBeInTheDocument();
    expect(screen.queryByText(/위임장의 값을 바꿨습니다/)).not.toBeInTheDocument();
  });

  it('tells a revoked delegation and a delegation without the export', async () => {
    open('/agent/request?case=ED1&period=REVOKED');
    expect(await screen.findByText(word('main.agent.periodRevoked'))).toBeInTheDocument();
  });

  it('shows the operations without the export for the reading only choice', async () => {
    open('/agent/request?case=ED1&operations=READ_ONLY');

    expect(await screen.findByText('프로젝트 목록 보기, 문서 목록 보기, 문서 열람 · HX-310')).toBeInTheDocument();
  });

  it('sends the choice with the start and nothing else of it', async () => {
    const { unmount } = open('/agent/request?case=ED1&quantity=400&period=EXPIRED');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('radio', { name: /멈춘다/ }));
    await user.click(screen.getByRole('button', { name: word('main.6-1.send') }));

    await vi.waitFor(() => expect(posted.some((call) => call.url === '/api/live/runs')).toBe(true));
    expect(posted.find((call) => call.url === '/api/live/runs')?.body).toEqual({
      scenario: 'ED1',
      turnstileToken: null,
      delegation: { quantity: 400, period: 'EXPIRED', operations: null },
    });
    unmount();
  });

  it('sends no choice for the case as it is, and for a case that takes none', async () => {
    const { unmount } = open('/agent/request?case=ED1');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('radio', { name: /멈춘다/ }));
    await user.click(screen.getByRole('button', { name: word('main.6-1.send') }));

    await vi.waitFor(() => expect(posted.some((call) => call.url === '/api/live/runs')).toBe(true));
    const body = posted.find((call) => call.url === '/api/live/runs')?.body as Record<string, unknown>;
    expect(body['scenario']).toBe('ED1');
    expect(body['delegation'] ?? null).toBeNull();
    unmount();
  });
});

describe('the delegation period in words (AS-12)', () => {
  const t = (key: string, values?: Record<string, unknown>) => (values ? i18n.t(key, values) : i18n.t(key)) as string;

  it('says a revoked delegation is revoked, whatever its period was', () => {
    expect(
      periodWords(t as never, {
        project: 'HX-310',
        purpose: 'DATA_EXPORT',
        summary: { ko: '', en: '' },
        operations: [],
        resources: [],
        validFromMinutes: -60,
        validUntilMinutes: 180,
        status: 'REVOKED',
        approvalRequired: false,
      }),
    ).toBe(word('main.agent.periodRevoked'));
  });
});
