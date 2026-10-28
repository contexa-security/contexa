import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import LabAgentPage from './LabAgentPage';
import LabEntrancePage from './LabEntrancePage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

const CASE = {
  key: 'T5',
  version: 1,
  title: { ko: '위임 만료 뒤의 예약 실행', en: 'A scheduled run after the delegation expired' },
  protagonist: 'eng-k',
  agentName: 'report',
  agentTitle: { ko: '보고서 에이전트', en: 'Report agent' },
  sender: 'DELEGATED_AGENT',
  instruction: { ko: '예약 실행', en: 'Scheduled run' },
  delegation: {
    project: 'HX-310',
    purpose: 'REPORTING',
    summary: { ko: 'HX-310 주간 도면 변경 보고서 작성', en: 'Prepare the weekly report' },
    operations: ['DOCUMENT_LIST'],
    resources: ['HX-310'],
    validFromMinutes: -10080,
    validUntilMinutes: -120,
    status: 'ACTIVE',
    approvalRequired: false,
  },
  classification: 'THREAT',
  normalPair: 'N1',
  recorded: { runId: 'run-t5', startedAt: '2026-10-24T04:46:33Z', runs: 18, sameAsLatest: 18 },
  normalRecorded: null,
};

const CONFIG = {
  scenarios: [],
  agentCases: [
    {
      key: 'T5',
      title: { ko: '위임 만료 뒤의 예약 실행', en: 'A scheduled run after the delegation expired' },
      classification: 'THREAT',
      subject: 'AGENT',
    },
  ],
  turnstileSiteKey: null,
  dailyRuns: 10,
  remainingToday: 10,
  agentRunPoints: 3,
  dailyAgentRuns: 2,
  remainingAgentToday: 2,
  paused: false,
};

let bodies: Record<string, unknown>;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  bodies = { '/api/visitor': { predictions: {} }, '/api/live/config': CONFIG, '/api/agent-cases/T5': CASE };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open(element: React.ReactElement, path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={element} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('the lab entrance has two doors (AS-6)', () => {
  it('names the person lab and the agent lab, each with its subject chip, and leads to each', async () => {
    open(<LabEntrancePage />, '/lab');

    const person = screen.getByRole('region', { name: word('lab.r7.entrance.person') });
    const agent = screen.getByRole('region', { name: word('lab.r7.entrance.agent') });
    expect(within(person).getByLabelText('보내는 쪽: 사람')).toBeInTheDocument();
    expect(within(agent).getByLabelText('보내는 쪽: 위임 에이전트')).toBeInTheDocument();
    expect(within(agent).getByRole('link', { name: word('lab.r7.entrance.agentGo') })).toHaveAttribute(
      'href',
      '/lab/agent',
    );
    expect(screen.getByRole('link', { name: word('lab.r7.entrance.next') })).toHaveAttribute('href', '/lab/case');
  });
});

describe('the agent lab (AS-6)', () => {
  it('shows each open agent case with its work given, its stored run and the way to run it', async () => {
    open(<LabAgentPage />, '/lab/agent');

    const cases = screen.getByRole('region', { name: word('labAgent.cases') });
    expect(await within(cases).findByText('위임 만료 뒤의 예약 실행')).toBeInTheDocument();
    expect(await within(cases).findByText('위임받은 일: HX-310 주간 도면 변경 보고서 작성')).toBeInTheDocument();
    // each card leads to the screens of its own case (AS-14)
    expect(within(cases).getByRole('link', { name: word('labAgent.recorded') })).toHaveAttribute(
      'href',
      '/agent/reason?case=T5',
    );
    expect(within(cases).getByRole('link', { name: word('labAgent.run') })).toHaveAttribute(
      'href',
      '/agent/request?case=T5',
    );
  });

  it('explains the three ways an agent sends requests, each with its own subject chip', () => {
    open(<LabAgentPage />, '/lab/agent');

    const paths = screen.getByRole('region', { name: word('labAgent.paths') });
    expect(within(paths).getByLabelText('보내는 쪽: 위임 에이전트')).toBeInTheDocument();
    expect(within(paths).getByLabelText('보내는 쪽: 단독 에이전트')).toBeInTheDocument();
    expect(within(paths).getByLabelText('보내는 쪽: 세션 에이전트')).toBeInTheDocument();
    expect(within(paths).getByText(word('labAgent.path.delegated'))).toBeInTheDocument();
    expect(within(paths).getByText(word('labAgent.path.autonomous'))).toBeInTheDocument();
    expect(within(paths).getByText(word('labAgent.path.session'))).toBeInTheDocument();
  });

  it('says how many agent runs the visitor has left today, as the portal counts them', async () => {
    bodies['/api/live/config'] = { ...CONFIG, remainingAgentToday: 1 };
    open(<LabAgentPage />, '/lab/agent');

    expect(
      await screen.findByText(
        word('labAgent.quota').replace('{{left}}', '1').replace('{{daily}}', '2').replace('{{points}}', '3'),
      ),
    ).toBeInTheDocument();
  });

  it('offers no run when no agent case is open, and says so', async () => {
    bodies['/api/live/config'] = { ...CONFIG, agentCases: [] };
    open(<LabAgentPage />, '/lab/agent');

    expect(await screen.findByText(word('labAgent.none'))).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: word('labAgent.run') })).not.toBeInTheDocument();
  });

  it('works against a portal that does not list agent cases yet (no field, no cases)', async () => {
    bodies['/api/live/config'] = { scenarios: [], dailyRuns: 10, remainingToday: 10, paused: false };
    open(<LabAgentPage />, '/lab/agent');

    expect(await screen.findByText(word('labAgent.none'))).toBeInTheDocument();
  });
});
