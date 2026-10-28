import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import AgentConfirmPage from './AgentConfirmPage';
import AgentConsolePage from './AgentConsolePage';
import AgentReasonPage from './AgentReasonPage';
import AgentRequestPage from './AgentRequestPage';
import { T5_CONFIRM_APPROVE } from './agentSnapshotFixture';

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
  instruction: {
    ko: '예약 실행: HX-310 도면 변경 보고서를 만드세요.',
    en: 'Scheduled run: prepare the HX-310 report.',
  },
  delegation: {
    project: 'HX-310',
    purpose: 'REPORTING',
    summary: {
      ko: 'HX-310 주간 도면 변경 보고서 작성',
      en: 'Prepare the weekly HX-310 drawing change report',
    },
    operations: ['PROJECT_LIST', 'DOCUMENT_LIST', 'DOCUMENT_READ'],
    resources: ['HX-310'],
    validFromMinutes: -10080,
    validUntilMinutes: -120,
    status: 'ACTIVE',
    approvalRequired: false,
  },
  classification: 'THREAT',
  normalPair: 'N1',
  recorded: { runId: 'run-t5recorded', startedAt: '2026-10-24T04:46:33Z' },
  normalRecorded: { runId: 'run-n1recorded', startedAt: '2026-10-24T04:30:00Z' },
};

interface Outcome {
  readonly outcome: string;
  readonly deliveredItems: number;
  readonly rule: string | null;
}

function outcomes(d: string, rule: string | null = null): Record<string, Outcome> {
  const passed: Outcome = { outcome: 'DELIVERED', deliveredItems: 0, rule: null };
  return { A: passed, B: passed, C1: passed, C2: passed, D: { outcome: d, deliveredItems: 0, rule } };
}

function agentRun(
  runId: string,
  confirmation: unknown,
  d = 'REFUSED',
  rule: string | null = 'AGENT_CONFIRMATION_REQUIRED',
) {
  return {
    runId,
    sender: 'DELEGATED_AGENT',
    agentModel: 'gpt-6-luna',
    instruction: 'Scheduled run',
    stopReason: 'ANSWERED',
    failure: null,
    finalAnswer: 'The request is pending confirmation.',
    startedAt: '2026-10-24T04:46:33Z',
    finishedAt: '2026-10-24T04:46:36Z',
    companyTime: '2026-10-26T14:00:00Z',
    steps: [
      {
        stepNo: 1,
        sentBy: 'AGENT_WORK',
        tool: { tool: 'listDocuments', arguments: { projectKey: 'HX-310' } },
        path: '/api/projects/HX-310/documents?type=DRAWING',
        companyTime: '2026-10-26T14:00:05Z',
        outcomes: outcomes(d, rule),
        decision: null,
      },
    ],
    confirmation,
    cost: { agent: { totalTokens: 1143 }, decisions: [] },
  };
}

const NORMAL = {
  ...agentRun('run-n1recorded', null, 'DELIVERED', null),
  finalAnswer: 'Report: revision C changes.',
};

let bodies: Record<string, unknown>;
let posted: { url: string; body: unknown }[];

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  posted = [];
  bodies = {
    '/api/visitor': { predictions: {} },
    '/api/journey': {
      state: { route: 'DEFAULT', act: 6, step: 'agent', differences: [] },
      runs: [],
      predictions: [],
    },
    '/api/agent-cases/T5': CASE,
    '/api/runs/run-t5recorded/agent': agentRun('run-t5recorded', {
      stepNo: 1,
      confirmationId: 'cfm-1',
      trigger: 'DELEGATION_ENDED',
      expiresAt: '2026-10-24T04:56:36Z',
      decision: null,
      reason: 'NOT_ASKED',
      askedAt: '2026-10-24T04:46:36Z',
      decidedAt: null,
      after: null,
      resend: null,
      reuse: null,
      other: null,
    }),
    '/api/runs/run-n1recorded/agent': NORMAL,
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        posted.push({ url, body: JSON.parse(String(init.body ?? 'null')) });
        return new Response(JSON.stringify(bodies['/api/live/runs/current'] ?? {}), { status: 200 });
      }
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

describe('the agent group names who sends (AS-1)', () => {
  it.each([
    ['6-1', <AgentRequestPage key="a" />, '/agent/request'],
    ['6-2', <AgentConsolePage key="b" />, '/agent/console'],
    ['6-3', <AgentReasonPage key="c" />, '/agent/reason'],
    ['6-4', <AgentConfirmPage key="d" />, '/agent/confirm'],
  ])('shows the case sender as a chip on %s', async (_number, element, path) => {
    open(element, path);

    expect(await screen.findByLabelText('보내는 쪽: 위임 에이전트')).toBeInTheDocument();
  });

  it('shows the kind of the sender the case records, not a fixed one', async () => {
    bodies['/api/agent-cases/T5'] = { ...CASE, sender: 'AUTONOMOUS_AGENT' };
    open(<AgentRequestPage />, '/agent/request');

    expect(await screen.findByLabelText('보내는 쪽: 단독 에이전트')).toBeInTheDocument();
    expect(screen.queryByLabelText('보내는 쪽: 위임 에이전트')).not.toBeInTheDocument();
  });
});

describe('a visitor with no run and a case with no recording (AC-5)', () => {
  beforeEach(() => {
    bodies['/api/agent-cases/T5'] = { ...CASE, recorded: null, normalRecorded: null };
    bodies['/api/agent-snapshots/T5-confirm-approve'] = T5_CONFIRM_APPROVE;
  });

  it('shows the stored real run on 6-3, marked as stored, with no model called for it', async () => {
    open(<AgentReasonPage />, '/agent/reason');

    expect(await screen.findByText(/실제 실행 · 저장된 기록/)).toBeInTheDocument();
    expect(await screen.findByRole('region', { name: '맡긴 일과 실제 요청을 나란히' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: word('main.6-2.toRequest') })).not.toBeInTheDocument();
  });

  it('does not stand the stored run in for the visitor run while it is still working', async () => {
    bodies['/api/live/runs/current'] = {
      liveRunId: 'live-3',
      scenario: 'T5',
      status: 'RUNNING',
      queuePosition: 0,
      queueWaitSeconds: null,
      runId: 'run-working',
      readyMs: 1000,
      steps: [],
      challenge: null,
      failure: null,
      awaitingStep: null,
      release: null,
      agentConfirmation: null,
    };
    open(<AgentConfirmPage />, '/agent/confirm');

    await screen.findByText(word('main.6-4.title.none'));
    const asked = (fetch as unknown as { mock: { calls: [string][] } }).mock.calls.map(([url]) =>
      String(url),
    );
    expect(asked).not.toContain('/api/agent-snapshots/T5-confirm-approve');
    expect(screen.queryByText(/실제 실행 · 저장된 기록/)).not.toBeInTheDocument();
  });

  it('shows the stored confirmation on 6-4, marked as stored', async () => {
    open(<AgentConfirmPage />, '/agent/confirm');

    expect(await screen.findByText(/실제 실행 · 저장된 기록/)).toBeInTheDocument();
    expect(await screen.findByText(word('main.6-4.title.approved'))).toBeInTheDocument();
  });
});

describe('6-1, giving the agent the work (docs/agent A7-3)', () => {
  it('shows the work given and its period as the case records them, and sends only after a call', async () => {
    open(<AgentRequestPage />, '/agent/request');

    expect(await screen.findByText('HX-310 주간 도면 변경 보고서 작성')).toBeInTheDocument();
    expect(screen.getByText('작업 시각 7일 전부터 2시간 전까지')).toBeInTheDocument();
    expect(screen.getByText('프로젝트 목록 보기, 문서 목록 보기, 문서 열람 · HX-310')).toBeInTheDocument();
    expect(screen.getByText(CASE.instruction.ko)).toBeInTheDocument();
    expect(screen.getByText(word('main.6-1.source'))).toBeInTheDocument();
    expect(screen.getByRole('button', { name: word('main.6-1.send') })).toBeDisabled();
  });

  // 구현계획 AC-N2: the first view says what the work is and asks one thing; it stays within 200 characters.
  it('stays within 200 characters at first sight, what the closed fold holds not counted', async () => {
    const { container } = open(<AgentRequestPage />, '/agent/request');
    await screen.findByText('HX-310 주간 도면 변경 보고서 작성');
    const main = container.querySelector('main')?.cloneNode(true) as HTMLElement;
    main.querySelectorAll('details:not([open]) > :not(summary)').forEach((hidden) => hidden.remove());
    expect((main.textContent ?? '').replace(/\s/g, '').length).toBeLessThanOrEqual(200);
  });

  it('has no side note under the two calls', async () => {
    open(<AgentRequestPage />, '/agent/request');
    await screen.findByText('HX-310 주간 도면 변경 보고서 작성');
    expect(screen.queryByText(word('main.request.noAnswer'))).toBeNull();
  });

  // 구현계획 NW-9 (R-N2): the objective and the period stay in view; what the employee wrote to the agent, the scope and
  // the agent's recent requests fold under one line.
  it('keeps the objective and the period in view and folds the instruction, the scope and the recent requests', async () => {
    const { container } = open(<AgentRequestPage />, '/agent/request');
    await screen.findByText('HX-310 주간 도면 변경 보고서 작성');
    const fold = container.querySelector('details[data-fold="agent-work"]') as HTMLDetailsElement | null;
    expect(fold).not.toBeNull();
    expect(fold?.open).toBe(false);
    expect(fold?.textContent).toContain(word('main.6-1.fold'));
    expect(fold?.textContent).toContain('프로젝트 목록 보기, 문서 목록 보기, 문서 열람 · HX-310');
    expect(fold?.textContent).toContain(word('main.6-1.recent'));
    expect(fold?.contains(screen.getByText('HX-310 주간 도면 변경 보고서 작성'))).toBe(false);
    expect(fold?.contains(screen.getByText('작업 시각 7일 전부터 2시간 전까지'))).toBe(false);
    expect(fold?.contains(screen.getByText(CASE.instruction.ko))).toBe(true);
    expect(fold?.contains(screen.getByText(word('main.6-1.source')))).toBe(true);
  });
});

describe('6-3, the delegation and the request (docs/agent A7-3)', () => {
  it("says the delegation record showed it only when the run's records make it true, from the recording", async () => {
    open(<AgentReasonPage />, '/agent/reason');

    expect(
      await screen.findByText(word('main.6-3.intro.proof').replace('{{step}}', '1')),
    ).toBeInTheDocument();
    expect(
      screen.getByText(word('main.agent.trigger.DELEGATION_ENDED'), { exact: false }),
    ).toBeInTheDocument();
    expect(screen.getByText(word('main.6-3.byRecord'))).toBeInTheDocument();
    const existing = screen.getByRole('region', { name: word('main.6-3.existing') });
    expect(within(existing).getAllByText(word('main.agent.outcome.DELIVERED'))).toHaveLength(4);
    expect(within(existing).getByText(word('main.agent.outcome.CONFIRM'))).toBeInTheDocument();
    expect(await screen.findByText(word('main.6-3.pairDone'))).toBeInTheDocument();
  });

  // 구현계획 AC-N2: the first view is the difference the engine named and the judgment; the two records set side by
  // side, the existing approaches' answers and the normal pair are one press away.
  it('keeps the difference and the judgment in view and folds the records set side by side, the existing approaches and the pair', async () => {
    const { container } = open(<AgentReasonPage />, '/agent/reason');
    await screen.findByText(word('main.6-3.pairDone'));
    const fold = container.querySelector('details[data-fold="agent-compare"]') as HTMLDetailsElement | null;
    expect(fold).not.toBeNull();
    expect(fold?.open).toBe(false);
    expect(fold?.textContent).toContain(word('main.agent.compare.title'));
    expect(fold?.contains(screen.getByRole('region', { name: word('main.6-3.existing') }))).toBe(true);
    expect(fold?.contains(screen.getByText(word('main.6-3.pairDone')))).toBe(true);
    expect(fold?.contains(screen.getByText(word('main.6-3.byRecord')))).toBe(false);
    expect(fold?.contains(screen.getByText(word('main.6-3.difference')))).toBe(false);
  });

  it('keeps the actors of the delegation chain and the two times of the difference with the compared records', async () => {
    const { container } = open(<AgentReasonPage />, '/agent/reason');
    await screen.findByText(word('main.6-3.pairDone'));
    const fold = container.querySelector('details[data-fold="agent-compare"]') as HTMLDetailsElement;
    expect(fold.querySelector('[aria-label]')).not.toBeNull();
    expect(fold.textContent).toContain('엔지니어 K');
    // the sentence of the difference is in view without the two clock times, which the compared rows hold
    const view = screen.getByText(word('main.agent.trigger.DELEGATION_ENDED'), { exact: false });
    expect(fold.contains(view)).toBe(false);
    expect(view.textContent).not.toMatch(/위임 끝/);
  });

  it('stays under 300 characters at first sight (AC-N3), what the closed fold holds not counted', async () => {
    const { container } = open(<AgentReasonPage />, '/agent/reason');
    await screen.findByText(word('main.6-3.pairDone'));
    const main = container.querySelector('main')?.cloneNode(true) as HTMLElement;
    main.querySelectorAll('details:not([open]) > :not(summary)').forEach((hidden) => hidden.remove());
    expect((main.textContent ?? '').replace(/\s/g, '').length).toBeLessThan(300);
  });

  it("reads the confirmation's trigger from the live run while it waits for the delegating person", async () => {
    bodies['/api/live/runs/current'] = {
      liveRunId: 'live-2',
      scenario: 'T5',
      status: 'CONFIRMING',
      queuePosition: 0,
      queueWaitSeconds: null,
      runId: 'run-t5waiting',
      readyMs: 1000,
      steps: [],
      challenge: null,
      failure: null,
      agentConfirmation: { stage: 'ASKED', secondsLeft: 100, stepNo: 1, trigger: 'DELEGATION_ENDED' },
    };
    bodies['/api/runs/run-t5waiting/agent'] = agentRun('run-t5waiting', null);
    open(<AgentReasonPage />, '/agent/reason');

    expect(
      await screen.findByText(word('main.6-3.intro.proof').replace('{{step}}', '1')),
    ).toBeInTheDocument();
    expect(
      screen.getByText(word('main.agent.trigger.DELEGATION_ENDED'), { exact: false }),
    ).toBeInTheDocument();
  });

  it('says plainly when the existing approaches stopped it too', async () => {
    const run = agentRun('run-t5recorded', null);
    const [first] = run.steps;
    if (first) {
      first.outcomes.C2 = { outcome: 'REFUSED', deliveredItems: 0, rule: 'APPROVAL_REQUIRED' };
    }
    bodies['/api/runs/run-t5recorded/agent'] = run;
    open(<AgentReasonPage />, '/agent/reason');

    expect(
      await screen.findByText(word('main.6-3.intro.plain').replace('{{step}}', '1')),
    ).toBeInTheDocument();
  });
});

describe('6-4, what reached the delegating person (docs/agent A7-3)', () => {
  // 구현계획 AC-N2: the difference and what the answer did are the view; the delegation record, the request asked about
  // and the authorization record's number are one press away.
  // 구현계획 AC-N2: the view is the title, the difference the engine named and the progress; what the answer led to, the
  // delegation record, the request asked about and the authorization number wait under one line.
  it('keeps what the answer led to with the delegation record under one line', async () => {
    bodies['/api/runs/run-t5recorded/agent'] = agentRun('run-t5recorded', {
      stepNo: 1,
      confirmationId: 'cfm-1',
      trigger: 'DELEGATION_ENDED',
      expiresAt: null,
      decision: 'APPROVE',
      reason: null,
      askedAt: '2026-10-24T04:46:36Z',
      decidedAt: '2026-10-24T04:47:10Z',
      after: { status: 'APPROVED', authorizationId: 'authz-7' },
      resend: { httpStatus: 200, outcome: 'DELIVERED', deliveredItems: 5, ruleId: null },
      reuse: { httpStatus: 403, outcome: 'REFUSED', deliveredItems: 0, ruleId: 'AGENT_CONFIRMATION_USED' },
      other: {
        httpStatus: 403,
        outcome: 'REFUSED',
        deliveredItems: 0,
        ruleId: 'AGENT_CONFIRMATION_MISMATCH',
      },
    });
    const { container } = open(<AgentConfirmPage />, '/agent/confirm');
    await screen.findByRole('heading', { level: 1, name: word('main.6-4.title.approved') });
    const folds = Array.from(container.querySelectorAll('details[data-fold]')).map((fold) =>
      fold.getAttribute('data-fold'),
    );
    // what the answer led to has no fold of its own: it waits with the record (the measurement note has its own line)
    expect(folds.filter((name) => name !== 'measure-note')).toEqual(['confirm-record']);
    const record = container.querySelector('details[data-fold="confirm-record"]') as HTMLDetailsElement;
    expect(record.open).toBe(false);
    expect(record.textContent).toContain('HTTP 200');
    expect(record.contains(screen.getByText(word('main.6-4.cost')))).toBe(true);
    expect(record.contains(screen.getByText(word('main.6-3.byRecord')))).toBe(true);
    expect(record.contains(screen.getByText(word('main.6-3.difference')))).toBe(false);
  });

  it('folds the delegation record, the request asked about and the authorization number under one line', async () => {
    bodies['/api/runs/run-t5recorded/agent'] = agentRun('run-t5recorded', {
      stepNo: 1,
      confirmationId: 'cfm-1',
      trigger: 'DELEGATION_ENDED',
      expiresAt: null,
      decision: 'APPROVE',
      reason: null,
      askedAt: '2026-10-24T04:46:36Z',
      decidedAt: '2026-10-24T04:47:10Z',
      after: { status: 'APPROVED', authorizationId: 'authz-7' },
      resend: { httpStatus: 200, outcome: 'DELIVERED', deliveredItems: 5, ruleId: null },
      reuse: { httpStatus: 403, outcome: 'REFUSED', deliveredItems: 0, ruleId: 'AGENT_CONFIRMATION_USED' },
      other: {
        httpStatus: 403,
        outcome: 'REFUSED',
        deliveredItems: 0,
        ruleId: 'AGENT_CONFIRMATION_MISMATCH',
      },
    });
    const { container } = open(<AgentConfirmPage />, '/agent/confirm');
    await screen.findByRole('heading', { level: 1, name: word('main.6-4.title.approved') });
    const fold = container.querySelector('details[data-fold="confirm-record"]') as HTMLDetailsElement | null;
    expect(fold).not.toBeNull();
    expect(fold?.open).toBe(false);
    expect(fold?.textContent).toContain(word('main.agent.work'));
    expect(fold?.textContent).toContain(word('main.6-4.request'));
    expect(fold?.textContent).toContain(word('main.6-4.authorization'));
    expect(fold?.contains(screen.getByText(word('main.6-3.difference')))).toBe(false);
    // the cost line is part of what the answer led to, so it waits in the fold too
    expect(fold?.contains(screen.getByText(word('main.6-4.cost')))).toBe(true);
  });

  it('lets the visitor answer as the delegating employee while the run waits', async () => {
    bodies['/api/live/runs/current'] = {
      liveRunId: 'live-1',
      scenario: 'T5',
      status: 'CONFIRMING',
      queuePosition: 0,
      queueWaitSeconds: null,
      runId: 'run-t5live',
      readyMs: 1000,
      steps: [],
      challenge: null,
      failure: null,
      agentConfirmation: {
        stage: 'ASKED',
        secondsLeft: 200,
        stepNo: 1,
        confirmationId: 'cfm-9',
        trigger: 'DELEGATION_ENDED',
        expiresAt: '2026-10-24T05:00:00Z',
        method: 'GET',
        target: '/api/projects/HX-310/documents?type=DRAWING',
        decision: null,
        cause: null,
        statusAfter: null,
        authorizationId: null,
        resendStatus: null,
        resendOutcome: null,
        resendDeliveredItems: null,
        reuseStatus: null,
        reuseRule: null,
        otherStatus: null,
        otherRule: null,
      },
    };
    bodies['/api/runs/run-t5live/agent'] = agentRun('run-t5live', null);
    open(<AgentConfirmPage />, '/agent/confirm');

    expect(
      await screen.findByRole('heading', { level: 1, name: word('main.6-4.title.asked') }),
    ).toBeInTheDocument();
    expect(await screen.findByText('남은 시간 200초')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: word('main.6-4.approve') }));

    expect(posted.filter((post) => post.url.startsWith('/api/live/'))).toEqual([
      { url: '/api/live/runs/current/agent-confirmation', body: { approve: true } },
    ]);
  });

  it('shows the authorization record and the engine refusing the same confirmation again', async () => {
    bodies['/api/runs/run-t5recorded/agent'] = agentRun('run-t5recorded', {
      stepNo: 1,
      confirmationId: 'cfm-1',
      trigger: 'DELEGATION_ENDED',
      expiresAt: null,
      decision: 'APPROVE',
      reason: null,
      askedAt: '2026-10-24T04:46:36Z',
      decidedAt: '2026-10-24T04:47:10Z',
      after: { status: 'APPROVED', authorizationId: 'authz-7' },
      resend: { httpStatus: 200, outcome: 'DELIVERED', deliveredItems: 5, ruleId: null },
      reuse: { httpStatus: 403, outcome: 'REFUSED', deliveredItems: 0, ruleId: 'AGENT_CONFIRMATION_USED' },
      other: {
        httpStatus: 403,
        outcome: 'REFUSED',
        deliveredItems: 0,
        ruleId: 'AGENT_CONFIRMATION_MISMATCH',
      },
    });
    open(<AgentConfirmPage />, '/agent/confirm');

    expect(
      await screen.findByRole('heading', { level: 1, name: word('main.6-4.title.approved') }),
    ).toBeInTheDocument();
    expect(screen.getByText('authz-7')).toBeInTheDocument();
    expect(screen.getByText('처리됨 · HTTP 200 · 5건')).toBeInTheDocument();
    // the refusals read by their status, and the engine's rule codes wait in the fold with the authorization record
    expect(screen.getAllByText('거부됨 · HTTP 403')).toHaveLength(2);
    const record = document.querySelector('details[data-fold="confirm-record"]');
    expect(record?.contains(screen.getByText('AGENT_CONFIRMATION_USED'))).toBe(true);
    expect(record?.contains(screen.getByText('AGENT_CONFIRMATION_MISMATCH'))).toBe(true);
    expect(screen.getByText(word('main.6-4.cost'))).toBeInTheDocument();
  });
});

describe('6-2, the live decision console of the agent (docs/agent A7-3)', () => {
  it("shows the visitor's run row by row with the confirmation asked of the delegating person", async () => {
    bodies['/api/journey'] = {
      state: { route: 'DEFAULT', act: 6, step: 'agent', differences: [] },
      runs: [
        {
          runId: 'run-t5mine',
          scenarioKey: 'T5',
          classification: 'THREAT',
          status: 'COMPLETED',
          lab: false,
          business: { D: 'STOPPED' },
          engineAction: null,
          exposedItems: 0,
          correct: true,
          requestedItems: null,
          steps: 0,
        },
      ],
      predictions: [],
    };
    bodies['/api/runs/run-t5mine/agent'] = agentRun('run-t5mine', null);
    open(<AgentConsolePage />, '/agent/console');

    expect(await screen.findByText('/api/projects/HX-310/documents?type=DRAWING')).toBeInTheDocument();
    expect(screen.getByText(word('main.6-2.confirmAsked'))).toBeInTheDocument();
    expect(screen.getByText('The request is pending confirmation.')).toBeInTheDocument();
    expect(screen.getByText(word('main.6-2.noAnalysis'))).toBeInTheDocument();
  });
});
