import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LiveAgentConfirmation, LiveRunView } from '../../../../api/types';
import i18n from '../../../../i18n';
import caseED1 from '../../../test/fixtures/agent-case-ED1.test.json';
import caseM10A from '../../../test/fixtures/agent-case-M10A.test.json';
import caseM14A from '../../../test/fixtures/agent-case-M14A.test.json';
import caseM22A from '../../../test/fixtures/agent-case-M22A.test.json';
import caseN1 from '../../../test/fixtures/agent-case-N1.test.json';
import caseT5 from '../../../test/fixtures/agent-case-T5.test.json';
import runN1 from '../../../test/fixtures/agent-run-n1.test.json';
import runT5 from '../../../test/fixtures/agent-run-t5-approve.test.json';
import anatomyN1 from '../../../test/fixtures/anatomy-n1-last.test.json';
import factsN1 from '../../../test/fixtures/facts-n1-last.test.json';
import liveConfig from '../../../test/fixtures/live-config.test.json';
import qualityN1 from '../../../test/fixtures/quality-n1-last.test.json';
import reportT5 from '../../../test/fixtures/snapshot-t5-report.test.json';
import stats from '../../../test/fixtures/stats.test.json';
import { renderAt, stubPortal, type PortalStub } from '../../../test/portal';
import AgentLivePage from './LivePage';
import AgentPickPage from './PickPage';
import AgentResultPage from './ResultPage';
import AgentReviewPage from './ReviewPage';

const T5_RUN = runT5.runId;
const N1_RUN = runN1.runId;
const N1_LAST = runN1.steps[runN1.steps.length - 1]?.stepNo ?? 1;
const JOURNEY = {
  state: { route: 'DEFAULT', act: 0, step: 'start', differences: [], predictions: {} },
  runs: [],
  predictions: [],
};

/** The portal's real answers (src/ux/test/fixtures, 2026-10-31) by the paths the agent screens read. */
const BASE: Record<string, unknown> = {
  '/api/visitor': { predictions: {}, csrfHeader: 'X-XSRF-TOKEN' },
  '/api/journey': JOURNEY,
  '/api/stats': stats,
  '/api/live/config': liveConfig,
  '/api/agent-cases/T5': caseT5,
  '/api/agent-cases/N1': caseN1,
  '/api/agent-cases/M22A': caseM22A,
  '/api/agent-cases/M10A': caseM10A,
  '/api/agent-cases/M14A': caseM14A,
  '/api/agent-cases/ED1': caseED1,
  [`/api/runs/${T5_RUN}/agent`]: runT5,
  [`/api/runs/${N1_RUN}/agent`]: runN1,
  [`/api/runs/${N1_RUN}/steps/${N1_LAST}/anatomy`]: anatomyN1,
  [`/api/runs/${N1_RUN}/steps/${N1_LAST}/quality`]: qualityN1,
  [`/api/runs/${N1_RUN}/steps/${N1_LAST}/facts`]: factsN1,
  '/api/agent-snapshots/T5-confirm-report': reportT5,
};

function serve(extra: PortalStub['get'] = {}, postAnswers: PortalStub['postAnswers'] = {}) {
  return stubPortal({ get: { ...BASE, ...extra }, postAnswers });
}

function flow(address: string) {
  return renderAt(
    address,
    <Routes>
      <Route path="/simulate/agent" element={<AgentPickPage />} />
      <Route path="/simulate/agent/:caseKey/review" element={<AgentReviewPage />} />
      <Route path="/simulate/agent/:caseKey/live" element={<AgentLivePage />} />
      <Route path="/simulate/agent/:caseKey/result" element={<AgentResultPage />} />
    </Routes>,
  );
}

function liveView(over: Partial<LiveRunView>): LiveRunView {
  return {
    liveRunId: 'live-a1',
    scenario: 'T5',
    status: 'RUNNING',
    queuePosition: 0,
    queueWaitSeconds: null,
    runId: null,
    readyMs: null,
    steps: [],
    challenge: null,
    failure: null,
    ...over,
  };
}

function confirmation(over: Partial<LiveAgentConfirmation>): LiveAgentConfirmation {
  return {
    stage: 'ASKED',
    secondsLeft: 840,
    stepNo: 1,
    confirmationId: 'c-1',
    trigger: 'DELEGATION_ENDED',
    expiresAt: null,
    method: 'GET',
    target: '/api/projects/HX-310/documents',
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
    ...over,
  };
}

const DELIVERED = { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 1, elapsedMs: 20 } as const;
const ASKED_LAYERS = {
  A: DELIVERED,
  B: DELIVERED,
  C1: DELIVERED,
  C2: DELIVERED,
  D: {
    outcome: 'REFUSED',
    httpStatus: 403,
    deliveredItems: 0,
    elapsedMs: 30,
    ruleId: 'AGENT_CONFIRMATION_REQUIRED',
  },
} as unknown as LiveRunView['steps'][number]['layers'];

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  sessionStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('step 1: the agent scenarios', () => {
  it('shows the delegation chain and the open cases in the designed order, each with its truth and instruction', async () => {
    serve();
    flow('/simulate/agent');
    const chain = await screen.findByRole('region', { name: '위임 사슬' });
    expect(await within(chain).findByText('엔지니어 K')).toBeInTheDocument();
    expect(within(chain).getByText('보고서 에이전트')).toBeInTheDocument();
    expect(within(chain).getByText('HX-310 문서')).toBeInTheDocument();
    const cards = await screen.findAllByRole('article');
    expect(cards.map((card) => within(card).getAllByText(/^(T5|N1|M22A|M10A|M14A)$/)[0]?.textContent)).toEqual([
      'T5',
      'N1',
      'M22A',
      'M10A',
      'M14A',
    ]);
    const t5 = screen.getByRole('article', { name: caseT5.title.ko });
    expect(within(t5).getByText('권장 시작')).toBeInTheDocument();
    expect(within(t5).getByText('정답: 위협')).toBeInTheDocument();
    expect(await within(t5).findByText(caseT5.instruction.ko)).toBeInTheDocument();
    expect(within(t5).getByText('보고서 작성 · 기간 종료')).toBeInTheDocument();
    expect(within(t5).getByRole('link', { name: `${caseT5.title.ko} 선택` })).toHaveAttribute(
      'href',
      '/simulate/agent/T5/review',
    );
    const n1 = screen.getByRole('article', { name: caseN1.title.ko });
    expect(within(n1).getByText('대조군')).toBeInTheDocument();
    const m14a = screen.getByRole('article', { name: caseM14A.title.ko });
    expect(within(m14a).getByText('정답 미지정 · 판정이 갈리는 시나리오')).toBeInTheDocument();
    expect(await within(m14a).findByText(/점수에서 제외/)).toBeInTheDocument();
    const m10a = screen.getByRole('article', { name: caseM10A.title.ko });
    expect(await within(m10a).findByText('위임 등록 없음')).toBeInTheDocument();
  });
});

describe('step 2: the delegation and the call', () => {
  it('shows the delegation as recorded: purpose, scope, the period that ended before the request, and the instruction', async () => {
    serve();
    flow('/simulate/agent/T5/review');
    expect(await screen.findByRole('heading', { level: 1, name: caseT5.title.ko })).toBeInTheDocument();
    const delegation = screen.getByRole('region', { name: '회사가 기록한 위임' });
    expect(within(delegation).getByText(caseT5.delegation.summary.ko)).toBeInTheDocument();
    for (const scope of ['프로젝트 목록 보기', '문서 목록 보기', '문서 열람', 'HX-310']) {
      expect(within(delegation).getAllByText(scope).length).toBeGreaterThan(0);
    }
    expect(within(delegation).getByText(/작업 시각 7일 전부터 2시간 전까지/)).toBeInTheDocument();
    expect(within(delegation).getByText('기간 종료')).toBeInTheDocument();
    expect(within(delegation).getByText(caseT5.instruction.ko)).toBeInTheDocument();
    expect(screen.getByText('에이전트 실행 방문자당 하루 2회 · 오늘 남은 2회')).toBeInTheDocument();
  });

  it('saves the main case call with the portal before sending the run (DEC-35) and opens step 3', async () => {
    const posts = serve(
      {},
      {
        '/api/journey': { status: 200, body: JOURNEY },
        '/api/live/runs': { status: 202, body: liveView({ status: 'QUEUED' }) },
      },
    );
    flow('/simulate/agent/T5/review');
    const run = await screen.findByRole('button', { name: '에이전트 실행' });
    await waitFor(() => expect(run).toHaveAccessibleDescription('예상 판정을 고르면 실행할 수 있습니다'));
    await userEvent.click(screen.getByRole('radio', { name: /중단 · 위임자 확인/ }));
    await waitFor(() => expect(run).not.toHaveAttribute('aria-disabled'));
    await userEvent.click(run);
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/simulate/agent/T5/live'));
    expect(posts.map((post) => post.path)).toEqual(['/api/journey', '/api/live/runs']);
    expect(posts[0]?.body).toEqual({ prediction: { experience: 'E4', engine: 'BLOCK' } });
    expect(posts[1]?.body).toEqual({ scenario: 'T5', turnstileToken: null });
  });

  it('keeps the call of a case the portal does not score in this browser only, and sends no journey', async () => {
    const posts = serve({}, { '/api/live/runs': { status: 202, body: liveView({ scenario: 'N1' }) } });
    flow('/simulate/agent/N1/review');
    await userEvent.click(await screen.findByRole('radio', { name: /처리/ }));
    const run = screen.getByRole('button', { name: '에이전트 실행' });
    await waitFor(() => expect(run).not.toHaveAttribute('aria-disabled'));
    await userEvent.click(run);
    await waitFor(() => expect(posts.map((post) => post.path)).toEqual(['/api/live/runs']));
    expect(sessionStorage.getItem('ux.agent.call.N1')).toBe('ALLOW');
  });

  it('sends the delegation the address changed, marked where it shows (ST-31)', async () => {
    const query = '?quantity=400&period=EXPIRED&operations=READ_ONLY';
    const posts = serve(
      { [`/api/agent-cases/ED1${query}`]: caseED1 },
      { '/api/live/runs': { status: 202, body: liveView({ scenario: 'ED1' }) } },
    );
    flow(`/simulate/agent/ED1/review${query}`);
    expect(await screen.findByRole('heading', { level: 1, name: caseED1.title.ko })).toBeInTheDocument();
    expect(screen.getAllByText('바꾼 값').length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole('radio', { name: /중단 · 위임자 확인/ }));
    const run = screen.getByRole('button', { name: '에이전트 실행' });
    await waitFor(() => expect(run).not.toHaveAttribute('aria-disabled'));
    await userEvent.click(run);
    await waitFor(() => expect(posts.some((post) => post.path === '/api/live/runs')).toBe(true));
    expect(posts.find((post) => post.path === '/api/live/runs')?.body).toEqual({
      scenario: 'ED1',
      turnstileToken: null,
      delegation: { quantity: 400, period: 'EXPIRED', operations: 'READ_ONLY' },
    });
  });

  it('locks the run once the day\'s agent runs are used, and names the refusal of the agent limit (ST-22)', async () => {
    serve({ '/api/live/config': { ...liveConfig, remainingAgentToday: 0 } });
    flow('/simulate/agent/T5/review');
    const run = await screen.findByRole('button', { name: '에이전트 실행' });
    await waitFor(() => expect(run).toHaveAccessibleDescription('오늘 에이전트 실행을 모두 썼습니다'));
  });

  it('says the agent limit when the portal refuses with AGENT_LIMIT, and leads to the stored real run (ST-22, ST-29)', async () => {
    serve(
      { '/api/agent-snapshots/T5-confirm-approve': { label: 'T5-confirm-approve', runId: T5_RUN } },
      {
        '/api/journey': { status: 200, body: JOURNEY },
        '/api/live/runs': { status: 429, body: { reason: 'AGENT_LIMIT' } },
      },
    );
    flow('/simulate/agent/T5/review');
    await userEvent.click(await screen.findByRole('radio', { name: /처리/ }));
    const run = screen.getByRole('button', { name: '에이전트 실행' });
    await waitFor(() => expect(run).not.toHaveAttribute('aria-disabled'));
    await userEvent.click(run);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('오늘 에이전트 실행을 모두 썼습니다. 저장된 실제 실행은 계속 볼 수 있습니다.');
    expect(within(alert).getByRole('link', { name: '같은 시나리오의 저장된 실제 실행 보기' })).toHaveAttribute(
      'href',
      `/runs/${T5_RUN}`,
    );
  });

  it('says a pause when the agent runs at once are full (ST-21)', async () => {
    serve({}, {
      '/api/journey': { status: 200, body: JOURNEY },
      '/api/live/runs': { status: 409, body: { reason: 'AGENT_BUSY' } },
    });
    flow('/simulate/agent/T5/review');
    await userEvent.click(await screen.findByRole('radio', { name: /처리/ }));
    const run = screen.getByRole('button', { name: '에이전트 실행' });
    await waitFor(() => expect(run).not.toHaveAttribute('aria-disabled'));
    await userEvent.click(run);
    expect(await screen.findByRole('alert')).toHaveTextContent('실시간 실행이 잠시 멈춰 있습니다');
  });

  it('says when the company has no delegation on record (M10A) and when no answer is set (M14A, ST-30)', async () => {
    serve();
    const first = flow('/simulate/agent/M10A/review');
    expect(await screen.findByText('업무 컨텍스트에 이 에이전트의 위임이 없습니다. 토큰은 유효합니다.')).toBeInTheDocument();
    first.unmount();
    flow('/simulate/agent/M14A/review');
    expect(await screen.findByText(/정답 미지정 시나리오입니다/)).toBeInTheDocument();
  });

  it('leads a case the portal does not open back to step 1 (DEC-27)', async () => {
    serve();
    flow('/simulate/agent/S13/review');
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/simulate/agent'));
  });
});

describe('step 3: the agent at work and the delegating person', () => {
  it('says the agent is at work before its first request, then one row per request (ST-23)', async () => {
    serve({ '/api/live/runs/current': liveView({}) });
    const first = flow('/simulate/agent/T5/live');
    expect(await screen.findByText('에이전트가 작업을 시작했습니다. 첫 요청을 기다리는 중입니다.')).toBeInTheDocument();
    first.unmount();
    serve({
      '/api/live/runs/current': liveView({
        steps: [{ stepNo: 1, operation: 'DOCUMENT_LIST', layers: { A: DELIVERED, B: DELIVERED } }],
      }),
    });
    flow('/simulate/agent/T5/live');
    const table = await screen.findByRole('table', { name: '에이전트가 보낸 요청' });
    expect(within(table).getByText('문서 목록 보기')).toBeInTheDocument();
    expect(within(table).getAllByText('허용')).toHaveLength(2);
  });

  it('asks the visitor as the delegating person and sends the answer (ST-24)', async () => {
    const posts = serve(
      {
        '/api/live/runs/current': liveView({
          status: 'CONFIRMING',
          runId: T5_RUN,
          steps: [{ stepNo: 1, operation: 'DOCUMENT_LIST', layers: ASKED_LAYERS }],
          agentConfirmation: confirmation({}),
        }),
      },
      {
        '/api/live/runs/current/agent-confirmation': {
          status: 200,
          body: liveView({
            status: 'RUNNING',
            runId: T5_RUN,
            agentConfirmation: confirmation({ stage: 'DONE', decision: 'APPROVE', resendStatus: 200, resendDeliveredItems: 1 }),
          }),
        },
      },
    );
    flow('/simulate/agent/T5/live');
    const panel = await screen.findByRole('region', { name: '요청 1에 대한 위임자 확인' });
    expect(within(panel).getByText('위임자 엔지니어 K의 입장에서 답합니다')).toBeInTheDocument();
    expect(within(panel).getByText('위임 기간이 끝난 뒤의 요청입니다')).toBeInTheDocument();
    expect(within(panel).getByRole('timer')).toHaveTextContent('840초');
    expect(screen.getByRole('button', { name: '결과 · 판정 근거' })).toHaveAccessibleDescription(
      '위임자 확인에 답하면 이어집니다',
    );
    await userEvent.click(within(panel).getByRole('button', { name: '승인' }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]).toEqual({ path: '/api/live/runs/current/agent-confirmation', body: { approve: true } });
    expect(await screen.findByText('위임자가 승인했습니다')).toBeInTheDocument();
    expect(screen.getByText('다시 보낸 요청: HTTP 200 · 1건 전달')).toBeInTheDocument();
  });

  it('says why a confirmation ended without an answer (ST-26)', async () => {
    serve({
      '/api/live/runs/current': liveView({
        status: 'CONFIRMING',
        runId: T5_RUN,
        steps: [{ stepNo: 1, operation: 'DOCUMENT_LIST', layers: ASKED_LAYERS }],
        agentConfirmation: confirmation({ stage: 'EXPIRED', secondsLeft: 0 }),
      }),
    });
    flow('/simulate/agent/T5/live');
    expect(await screen.findByText('확인 시간이 지나 요청은 막힌 채 끝났습니다.')).toBeInTheDocument();
  });

  it('opens the result once the run is stored, with its record rows (ST-28)', async () => {
    serve({ '/api/live/runs/current': liveView({ status: 'COMPLETED', runId: T5_RUN }) });
    flow('/simulate/agent/T5/live');
    const result = await screen.findByRole('link', { name: '결과 · 판정 근거' });
    expect(result).toHaveAttribute('href', `/simulate/agent/T5/result?run=${T5_RUN}`);
    const table = screen.getByRole('table', { name: '에이전트가 보낸 요청' });
    expect(within(table).getByText('위임자 확인')).toBeInTheDocument();
  });

  it('offers a new run and a stored run when the run failed (ST-16)', async () => {
    serve({
      '/api/live/runs/current': liveView({ status: 'FAILED' }),
      '/api/agent-snapshots/T5-confirm-approve': { label: 'T5-confirm-approve', runId: T5_RUN },
    });
    flow('/simulate/agent/T5/live');
    expect(await screen.findByText(/에이전트 작업을 끝내지 못했습니다/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '다시 실행' })).toHaveAttribute('href', '/simulate/agent/T5/review');
    expect(await screen.findByRole('link', { name: '같은 시나리오의 저장된 실제 실행 보기' })).toHaveAttribute('href', `/runs/${T5_RUN}`);
  });
});

describe('step 4: the result', () => {
  it('concludes from the run record and sets the stored report beside the approval (DEC-26)', async () => {
    serve();
    flow(`/simulate/agent/T5/result?run=${T5_RUN}`);
    expect(
      await screen.findByRole('heading', { level: 1, name: '요청 1에서 위임자 확인을 요구했고, 위임자가 승인했습니다' }),
    ).toBeInTheDocument();
    expect(screen.getByText('기존 4개 통제는 모든 요청을 통과시켰습니다.')).toBeInTheDocument();
    const confirm = screen.getByRole('region', { name: '위임자 응답별 결과' });
    expect(within(confirm).getByText('위임자가 승인했습니다')).toBeInTheDocument();
    expect(await within(confirm).findByText('위임자가 신고했습니다')).toBeInTheDocument();
    expect(within(confirm).getByText(reportT5.runId)).toBeInTheDocument();
    expect(screen.getByText('이 실행에는 AI 판정 기록이 없습니다.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'N1 실행' })).toHaveAttribute('href', '/simulate/agent/N1/review');
  });

  it('shows every request let through with the engine\'s evidence, and the browser-kept call beside what happened', async () => {
    serve();
    sessionStorage.setItem('ux.agent.call.N1', 'BLOCK');
    flow(`/simulate/agent/N1/result?run=${N1_RUN}`);
    expect(
      await screen.findByRole('heading', { level: 1, name: `에이전트 요청 ${runN1.steps.length}건을 모두 처리했습니다` }),
    ).toBeInTheDocument();
    expect(screen.getByText('중단 · 위임자 확인 · 실제: 처리')).toBeInTheDocument();
    const evidence = screen.getByRole('region', { name: '판정 근거' });
    expect(await within(evidence).findAllByRole('listitem')).not.toHaveLength(0);
    const table = screen.getByRole('table', { name: '에이전트가 보낸 요청' });
    expect(within(table).getAllByRole('row')).toHaveLength(runN1.steps.length + 1);
  });
});
