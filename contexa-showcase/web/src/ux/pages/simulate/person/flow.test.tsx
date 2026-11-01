import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AnalysisView, LiveRunView } from '../../../../api/types';
import i18n from '../../../../i18n';
import anatomyAttacker from '../../../test/fixtures/anatomy-attacker.test.json';
import anatomyOwner from '../../../test/fixtures/anatomy-owner.test.json';
import beforeS13 from '../../../test/fixtures/before-S13.test.json';
import beforeS13T from '../../../test/fixtures/before-S13T.test.json';
import beforeS16 from '../../../test/fixtures/before-S16.test.json';
import benchmarkFull from '../../../test/fixtures/benchmark-full.test.json';
import factsAttacker from '../../../test/fixtures/facts-attacker.test.json';
import anatomyInsider2 from '../../../test/fixtures/anatomy-insider-2.test.json';
import factsInsider2 from '../../../test/fixtures/facts-insider-2.test.json';
import qualityInsider2 from '../../../test/fixtures/quality-insider-2.test.json';
import resultInsider2 from '../../../test/fixtures/result-insider-2.test.json';
import scoreInsider from '../../../test/fixtures/score-insider.test.json';
import hook from '../../../test/fixtures/hook.test.json';
import labOptions from '../../../test/fixtures/lab-options.test.json';
import liveConfig from '../../../test/fixtures/live-config.test.json';
import qualityAttacker from '../../../test/fixtures/quality-attacker.test.json';
import receivedAttacker from '../../../test/fixtures/received-attacker.test.json';
import receivedOwner from '../../../test/fixtures/received-owner.test.json';
import resultAttacker from '../../../test/fixtures/result-attacker.test.json';
import resultOwner from '../../../test/fixtures/result-owner.test.json';
import scoreAttacker from '../../../test/fixtures/score-attacker.test.json';
import scoreOwner from '../../../test/fixtures/score-owner.test.json';
import stats from '../../../test/fixtures/stats.test.json';
import { renderAt, stubPortal, type PortalStub } from '../../../test/portal';
import LivePage from './LivePage';
import PickPage from './PickPage';
import ResultPage from './ResultPage';
import ReviewPage from './ReviewPage';

const ATTACKER_RUN = 'run-63b23f7bb5b2';
const OWNER_RUN = 'run-0781df5c8463';

/** The portal's real answers (src/ux/test/fixtures, 2026-10-31) by the paths the screens read. */
const BASE: Record<string, unknown> = {
  '/api/visitor': { predictions: {}, csrfHeader: 'X-XSRF-TOKEN' },
  '/api/journey': {
    state: { route: 'DEFAULT', act: 0, step: 'start', differences: [], predictions: {} },
    runs: [],
    predictions: [],
  },
  '/api/hook': hook,
  '/api/stats': stats,
  '/api/live/config': liveConfig,
  '/api/lab/options': labOptions,
  '/api/live/before/S13?step=1': beforeS13,
  '/api/live/before/S13T?step=1': beforeS13T,
  '/api/live/before/S16?step=1': beforeS16,
  [`/api/runs/${beforeS13.comparison.runId}/steps/1/anatomy`]: anatomyAttacker,
  [`/api/runs/${ATTACKER_RUN}/steps/1/anatomy`]: anatomyAttacker,
  [`/api/runs/${ATTACKER_RUN}/steps/1/received`]: receivedAttacker,
  [`/api/runs/${ATTACKER_RUN}/steps/1/result`]: resultAttacker,
  [`/api/runs/${ATTACKER_RUN}/score`]: scoreAttacker,
  [`/api/runs/${ATTACKER_RUN}/steps/1/quality`]: qualityAttacker,
  [`/api/runs/${ATTACKER_RUN}/steps/1/facts`]: factsAttacker,
  [`/api/runs/${OWNER_RUN}/steps/1/anatomy`]: anatomyOwner,
  [`/api/runs/${OWNER_RUN}/steps/1/received`]: receivedOwner,
  [`/api/runs/${OWNER_RUN}/steps/1/result`]: resultOwner,
  [`/api/runs/${OWNER_RUN}/score`]: scoreOwner,
};

function journeyWith(runs: readonly { scenarioKey: string; runId: string }[]) {
  return {
    state: { route: 'DEFAULT', act: 0, step: 'start', differences: [], predictions: {} },
    runs: runs.map((run) => ({
      runId: run.runId,
      scenarioKey: run.scenarioKey,
      classification: null,
      status: 'COMPLETED',
      lab: false,
      business: {},
      engineAction: null,
      exposedItems: 0,
      correct: null,
      requestedItems: 480,
      steps: 1,
    })),
    predictions: [],
  };
}

function liveView(over: Partial<LiveRunView>): LiveRunView {
  return {
    liveRunId: 'live-1',
    scenario: 'S13',
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

const RULES_ANSWERED = {
  A: { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 480, elapsedMs: 50 },
  B: { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 480, elapsedMs: 29 },
  C1: { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 480, elapsedMs: 44 },
  C2: { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 480, elapsedMs: 58 },
} as const;

/**
 * A passed step-up as the portal returns the stored row (run_challenge): the attacker's real row's columns
 * (anatomy-attacker.test.json, which the attacker never passed), here answered and sent again.
 */
function passedCheck(stepNo: number, delivered: number) {
  return {
    ...anatomyAttacker.recovery.challenge,
    step_no: stepNo,
    answered: true,
    reason: null,
    code_requested_at: '2026-10-20T12:31:48.120Z',
    verified_at: '2026-10-20T12:32:05.402Z',
    reissue_sent_at: '2026-10-20T12:32:05.480Z',
    reissue_status: 200,
    reissue_outcome: 'DELIVERED',
    reissue_delivered: delivered,
    reissue_elapsed_ms: 61,
  };
}

/** The value a key-value row shows next to its name. */
function valueOf(scope: HTMLElement, name: string) {
  return within(scope).getByText(name).nextElementSibling;
}

function serve(extra: PortalStub['get'] = {}, postAnswers: PortalStub['postAnswers'] = {}) {
  return stubPortal({ get: { ...BASE, ...extra }, postAnswers });
}

function flow(address: string) {
  return renderAt(
    address,
    <Routes>
      <Route path="/simulate/person" element={<PickPage />} />
      <Route path="/simulate/person/:caseKey/review" element={<ReviewPage />} />
      <Route path="/simulate/person/:caseKey/live" element={<LivePage />} />
      <Route path="/simulate/person/:caseKey/result" element={<ResultPage />} />
    </Routes>,
  );
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('step 1: choosing the threat scenario', () => {
  it('forks one shared request into the compromised account and the legitimate user, each from its own device', async () => {
    serve();
    flow('/simulate/person');
    const shared = await screen.findByRole('region', {
      name: '공통 요청 — 같은 계정 · 같은 시각 · 같은 요청',
    });
    expect(await within(shared).findByText('엔지니어 K')).toBeInTheDocument();
    expect(within(shared).getByText('수요일 14:20')).toBeInTheDocument();
    expect(within(shared).getByText('비밀번호 + 일회용 코드')).toBeInTheDocument();
    expect(await within(shared).findByText('POST …/HX-310/exports')).toHaveAttribute(
      'title',
      '/api/projects/HX-310/exports',
    );
    const ato = screen.getByRole('article', { name: '탈취된 계정' });
    expect(await within(ato).findByText(/Safari 18 · macOS/)).toBeInTheDocument();
    expect(within(ato).getByText('기준선 이탈')).toBeInTheDocument();
    expect(within(ato).getByText('정답: 위협')).toBeInTheDocument();
    expect(within(ato).getByRole('link', { name: '탈취된 계정 선택' })).toHaveAttribute(
      'href',
      '/simulate/person/S13/review',
    );
    const owner = screen.getByRole('article', { name: '정상 사용자(계정 주인)' });
    expect(await within(owner).findByText(/Edge 140 · Windows/)).toBeInTheDocument();
    expect(within(owner).getByText('기준선 안')).toBeInTheDocument();
    expect(within(owner).getByText('정답: 정상 업무')).toBeInTheDocument();
    const insider = screen.getByRole('article', { name: '내부자 권한 남용' });
    expect(within(insider).getAllByRole('listitem')).toHaveLength(3);
    const groups = screen.getByRole('navigation', { name: '시나리오 묶음' });
    expect(
      within(groups)
        .getAllByRole('link')
        .map((link) => link.textContent),
    ).toEqual(['사람 계정 위협 3', 'AI 에이전트 위임 5', '요청 급증 1']);
  });
});

describe('step 2: reviewing the request and predicting', () => {
  it('shows the request as the engine received it in the latest run of the same scenario', async () => {
    serve();
    flow('/simulate/person/S13/review');
    expect(
      await screen.findByRole('heading', { level: 1, name: '설계 자료 480건 대량 반출 요청' }),
    ).toBeInTheDocument();
    const request = screen.getByRole('region', { name: '요청 사실' });
    const facts = await within(request).findAllByRole('term');
    expect(facts.map((term) => term.textContent)).toEqual([
      '계정',
      '요청 시각',
      '단말',
      '인증 방식',
      '반출 규모',
    ]);
    expect(within(request).getByText('480건')).toBeInTheDocument();
    expect(within(request).getByText('기준선 최대 15건')).toBeInTheDocument();
    expect(within(request).getAllByText('기준선 이탈')).toHaveLength(2);
    expect(within(request).getByText('HX-310 담당')).toBeInTheDocument();
    expect(within(request).getByText(beforeS13.comparison.runId)).toBeInTheDocument();
    // The business context already names the approval record; the scenario definition is not repeated.
    expect(within(request).getByText('승인 기록 없음')).toBeInTheDocument();
    expect(within(request).queryByText('자세히 · 시나리오 정의')).toBeNull();
  });

  it('keeps the scenario approval record when the business context names none (P-8, 5-1)', async () => {
    serve();
    flow('/simulate/person/S16/review');
    const request = await screen.findByRole('region', { name: '요청 사실' });
    expect(await within(request).findByText('HX-310 담당')).toBeInTheDocument();
    const definition = (await within(request).findByText('자세히 · 시나리오 정의')).closest(
      'details',
    ) as HTMLElement;
    expect(valueOf(definition, '승인 기록')).toHaveTextContent('없음');
  });

  it('runs only after an expected decision, saving it before the live run (ST-6 path to step 3)', async () => {
    const posts = serve(
      {},
      {
        '/api/journey': { status: 200, body: BASE['/api/journey'] },
        '/api/live/runs': { status: 202, body: liveView({ status: 'QUEUED' }) },
      },
    );
    flow('/simulate/person/S13/review');
    const run = await screen.findByRole('button', { name: '요청 실행' });
    await waitFor(() => expect(run).toHaveAccessibleDescription('예상 판정을 고르면 실행할 수 있습니다'));
    await userEvent.click(screen.getByRole('radio', { name: /차단 · 추가 인증/ }));
    await waitFor(() => expect(run).not.toHaveAttribute('aria-disabled'));
    await userEvent.click(run);
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/simulate/person/S13/live'));
    expect(posts.map((post) => [post.path, post.body])).toEqual([
      ['/api/journey', { prediction: { experience: 'E1', engine: 'BLOCK' } }],
      ['/api/live/runs', { scenario: 'S13', turnstileToken: null }],
    ]);
  });

  it.each([
    [429, 'DAILY', '오늘 실행할 수 있는 횟수를 모두 썼습니다.', true],
    [409, 'BUSY', '실시간 실행이 잠시 멈춰 있습니다.', true],
    [403, 'TURNSTILE_FAILED', '사람 확인이 거절되었습니다.', false],
    [500, 'ENGINE', '요청을 보내지 못했습니다.', true],
  ])(
    'says why a %i refusal stopped the run and leads to a stored real run (ST-2~ST-5)',
    async (status, reason, words, recorded) => {
      serve(
        {},
        {
          '/api/journey': { status: 200, body: BASE['/api/journey'] },
          '/api/live/runs': { status, body: { reason } },
        },
      );
      flow('/simulate/person/S13/review');
      await userEvent.click(await screen.findByRole('radio', { name: /허용/ }));
      await userEvent.click(screen.getByRole('button', { name: '요청 실행' }));
      const alert = await screen.findByRole('alert');
      expect(alert).toHaveTextContent(words);
      const link = within(alert).queryByRole('link', { name: '같은 시나리오의 저장된 실제 실행 보기' });
      if (recorded) {
        expect(link).toHaveAttribute('href', `/runs/${ATTACKER_RUN}`);
      } else {
        expect(link).toBeNull();
      }
    },
  );

  it('never stays locked when the request gets no answer (ST-5, the old button stayed on sending)', async () => {
    serve();
    const original = globalThis.fetch;
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) =>
      init?.method === 'POST' && String(input) === '/api/live/runs'
        ? Promise.reject(new TypeError('offline'))
        : original(input, init),
    );
    flow('/simulate/person/S13/review');
    await userEvent.click(await screen.findByRole('radio', { name: /허용/ }));
    const run = screen.getByRole('button', { name: '요청 실행' });
    await userEvent.click(run);
    expect(await screen.findByRole('alert')).toHaveTextContent('요청을 보내지 못했습니다.');
    expect(run).not.toHaveAttribute('aria-busy');
  });

  it('waits for the visitor earlier run and says so (ST-6)', async () => {
    serve(
      { '/api/live/runs/current': liveView({ scenario: 'S16', liveRunId: 'live-0' }) },
      {
        '/api/journey': { status: 200, body: BASE['/api/journey'] },
        '/api/live/runs': { status: 202, body: liveView({ scenario: 'S16', liveRunId: 'live-0' }) },
      },
    );
    flow('/simulate/person/S13/review');
    await userEvent.click(await screen.findByRole('radio', { name: /허용/ }));
    await userEvent.click(screen.getByRole('button', { name: '요청 실행' }));
    expect(
      await screen.findByText('앞서 보낸 요청이 끝나는 중입니다. 끝나는 대로 이어서 보냅니다.'),
    ).toBeInTheDocument();
  });

  it('asks for the human check when the portal requires one (ST-1)', async () => {
    serve({ '/api/live/config': { ...liveConfig, turnstileSiteKey: 'site-key' } });
    flow('/simulate/person/S13/review');
    await userEvent.click(await screen.findByRole('radio', { name: /허용/ }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '요청 실행' })).toHaveAccessibleDescription(
        '사람 확인을 마치면 실행할 수 있습니다',
      ),
    );
  });
});

const ANALYSIS_RUNNING: AnalysisView = {
  stepNo: 1,
  stages: [
    {
      type: 'CONTEXT_COLLECTED',
      atMs: 40,
      action: null,
      layer: null,
      riskScore: null,
      confidence: null,
      elapsedMs: null,
      mitre: null,
    },
    {
      type: 'LAYER1_START',
      atMs: 40,
      action: null,
      layer: 'LAYER1',
      riskScore: null,
      confidence: null,
      elapsedMs: null,
      mitre: null,
    },
  ],
  decision: null,
  decisionWait: { medianMs: 8650, decisions: 5, settingHash: 'h', waitedMs: 3200, remainingSeconds: 6 },
};

describe('step 3: the live decision', () => {
  it('fills the rows as the answers arrive while Contexa holds the response (ST-8)', async () => {
    serve({
      '/api/live/runs/current': liveView({
        steps: [{ stepNo: 1, operation: 'EXPORT', layers: RULES_ANSWERED }],
      }),
      '/api/live/runs/current/analysis?step=1': ANALYSIS_RUNNING,
    });
    flow('/simulate/person/S13/live');
    expect(await screen.findByText('Contexa 판정 중 · 3.2초 경과')).toBeInTheDocument();
    const table = screen.getByRole('table', { name: '5개 보안 통제의 응답' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows[0]).toHaveTextContent('허용480건0.050초');
    expect(rows[4]).toHaveTextContent('판정 중');
    expect(screen.getByText('0.058초 안에 모두 허용')).toBeInTheDocument();
    const progress = screen.getByRole('region', { name: 'Contexa 판정 진행' });
    expect(
      within(progress)
        .getAllByRole('listitem')
        .filter((item) => item.hasAttribute('data-state'))
        .map((item) => item.getAttribute('data-state')),
    ).toEqual(['done', 'done', 'done', 'now', 'wait']);
    expect(screen.getByRole('button', { name: '결과 · 판정 근거' })).toHaveAccessibleDescription(
      '판정이 끝나면 열립니다',
    );
  });

  it('opens the result once the decision is applied and the run is stored', async () => {
    serve({
      '/api/live/runs/current': liveView({
        status: 'COMPLETED',
        runId: ATTACKER_RUN,
        steps: [
          {
            stepNo: 1,
            operation: 'EXPORT',
            layers: {
              ...RULES_ANSWERED,
              D: { outcome: 'HELD', httpStatus: 401, deliveredItems: 0, elapsedMs: 8742 },
            },
          },
        ],
      }),
      '/api/live/runs/current/analysis?step=1': {
        ...ANALYSIS_RUNNING,
        stages: [
          ...ANALYSIS_RUNNING.stages,
          {
            type: 'LAYER1_COMPLETE',
            atMs: 8690,
            action: 'CHALLENGE',
            layer: 'LAYER1',
            riskScore: 0.35,
            confidence: 0.78,
            elapsedMs: 8650,
            mitre: null,
          },
          {
            type: 'DECISION_APPLIED',
            atMs: 8690,
            action: 'CHALLENGE',
            layer: null,
            riskScore: null,
            confidence: null,
            elapsedMs: null,
            mitre: null,
          },
        ],
        decision: {
          finalAction: 'CHALLENGE',
          proposedAction: 'CHALLENGE',
          unresolved: false,
          riskScore: 0.35,
          confidence: 0.78,
          applied: 'BEFORE_RESPONSE',
          reason: null,
          adverseLabels: [],
          adverseMet: 0,
          adverseChecked: 0,
          totalAnalysisMs: 8650,
          modelCalls: 1,
          promptTokens: 6787,
          completionTokens: 704,
        },
        decisionWait: null,
      },
      '/api/benchmark': benchmarkFull,
    });
    flow('/simulate/person/S13/live');
    const link = await screen.findByRole('link', { name: '결과 · 판정 근거' });
    expect(link).toHaveAttribute('href', `/simulate/person/S13/result?run=${ATTACKER_RUN}`);
    const table = screen.getByRole('table', { name: '5개 보안 통제의 응답' });
    expect(within(table).getAllByRole('row')[5]).toHaveTextContent('추가 인증0건8.7초');
    expect(await screen.findByText('학습 요청 49건 기준선 · 9개 항목 중 2개 이탈')).toBeInTheDocument();
    expect(screen.getByText('시스템 규칙 91줄 + 요청 상황 61줄')).toBeInTheDocument();
    expect(screen.getByText(/gpt-6-luna · 입력 6,787 · 출력 704 토큰/)).toBeInTheDocument();
    // P-8 (2-2): the engine's events at their recorded times, each model call, and the measurement of the scenario.
    const record = screen.getByText('자세히 · 엔진 기록').closest('details') as HTMLElement;
    const events = within(record)
      .getAllByRole('listitem')
      .map((item) => item.textContent);
    expect(events.slice(0, 4)).toEqual([
      '업무 컨텍스트 수집+0.040초',
      'AI 분석 시작+0.040초',
      'AI 분석 완료 · CHALLENGE · 위험도 0.35 · 확신도 0.78+8.7초',
      '판정 적용+8.7초',
    ]);
    expect(await within(record).findByText('호출 1 · 8.6초 · 입력 6,215 · 출력 660 토큰')).toBeInTheDocument();
    expect(
      await within(record).findByText('같은 시나리오 측정 1회 · Contexa 판정 추가 인증 1건'),
    ).toBeInTheDocument();
  });

  it('names the first and the second pass when the engine analysed twice (P-8, 2-2)', async () => {
    const stage = (type: string, atMs: number, extra: Partial<AnalysisView['stages'][number]> = {}) => ({
      type,
      atMs,
      action: null,
      layer: null,
      riskScore: null,
      confidence: null,
      elapsedMs: null,
      mitre: null,
      ...extra,
    });
    serve({
      '/api/live/runs/current': liveView({
        steps: [{ stepNo: 1, operation: 'EXPORT', layers: RULES_ANSWERED }],
      }),
      '/api/live/runs/current/analysis?step=1': {
        ...ANALYSIS_RUNNING,
        stages: [
          ...ANALYSIS_RUNNING.stages,
          stage('LAYER1_COMPLETE', 6120, { action: 'ESCALATE', riskScore: 0.55, confidence: 0.4 }),
          stage('LAYER2_START', 6130),
        ],
      },
    });
    flow('/simulate/person/S13/live');
    const record = (await screen.findByText('자세히 · 엔진 기록')).closest('details') as HTMLElement;
    expect(
      within(record)
        .getAllByRole('listitem')
        .map((item) => item.textContent),
    ).toEqual([
      '업무 컨텍스트 수집+0.040초',
      'AI 1차 분석 시작+0.040초',
      'AI 1차 분석 완료 · ESCALATE · 위험도 0.55 · 확신도 0.40+6.1초',
      'AI 2차 분석 시작+6.1초',
    ]);
  });

  it('says it is not sent yet when there is no run (ST-19), and why a run ended without a decision (ST-16)', async () => {
    serve();
    const first = flow('/simulate/person/S13/live');
    expect(await screen.findByText(/이 시나리오를 아직 실행하지 않았습니다/)).toBeInTheDocument();
    first.unmount();
    serve({ '/api/live/runs/current': liveView({ status: 'FAILED' }) });
    flow('/simulate/person/S13/live');
    expect(await screen.findByText(/판정을 끝내지 못했습니다/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '다시 실행' })).toHaveAttribute(
      'href',
      '/simulate/person/S13/review',
    );
    expect(
      await screen.findByRole('link', { name: '같은 시나리오의 저장된 실제 실행 보기' }),
    ).toHaveAttribute('href', `/runs/${ATTACKER_RUN}`);
  });

  it('shows the place in the queue (ST-7)', async () => {
    serve({
      '/api/live/runs/current': liveView({ status: 'QUEUED', queuePosition: 2, queueWaitSeconds: 30 }),
    });
    flow('/simulate/person/S13/live');
    expect(await screen.findByText('대기 순서 2번 약 30초 남았습니다')).toBeInTheDocument();
  });

  it('asks for the code at once for the compromised account, which never gets it (ST-9)', async () => {
    const waiting = liveView({
      status: 'CHALLENGE',
      challenge: {
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
      } as never,
    });
    const posts = serve(
      { '/api/live/runs/current': waiting },
      {
        '/api/live/runs/current/code': {
          status: 200,
          body: { ...waiting, challenge: { ...waiting.challenge, stage: 'NO_MAILBOX' } },
        },
      },
    );
    flow('/simulate/person/S13/live');
    expect(await screen.findByText(/추가 인증 코드는 계정 주인의 메일함으로 가서/)).toBeInTheDocument();
    expect(posts.map((post) => post.path)).toEqual(['/api/live/runs/current/code']);
  });

  it('lets the account owner pass the step-up with the inbox code (ST-10, ST-11, ST-13)', async () => {
    const challenge = (stage: string, extra: Record<string, unknown> = {}) =>
      liveView({
        scenario: 'S13T',
        status: 'CHALLENGE',
        challenge: {
          stage,
          code: null,
          secondsLeft: 100,
          attempts: 0,
          error: null,
          cause: null,
          codeRequestedMs: null,
          verifiedMs: null,
          reissueSentMs: null,
          reissueDoneMs: null,
          reissueStatus: null,
          ...extra,
        } as never,
      });
    const posts = serve(
      {
        '/api/live/runs/current': challenge('WAITING'),
        '/api/live/before/S13T?step=1': beforeS13T,
      },
      {
        '/api/live/runs/current/code': {
          status: 200,
          body: challenge('CODE_SHOWN', { code: '482913', error: 'WRONG_CODE', attempts: 1 }),
        },
        '/api/live/runs/current/answer': {
          status: 200,
          body: challenge('DONE', { reissueDeliveredItems: 480, reissueStatus: 200, reissueDoneMs: 900 }),
        },
      },
    );
    flow('/simulate/person/S13T/live');
    const card = await screen.findByRole('region', { name: '추가 인증 요구' });
    expect(within(card).getByRole('timer')).toHaveTextContent('100초 남음');
    await userEvent.click(within(card).getByRole('button', { name: '코드 받기' }));
    expect(await within(card).findByTestId('inbox-code')).toHaveTextContent('482913');
    expect(within(card).getByText('코드가 맞지 않습니다(1/3)')).toBeInTheDocument();
    await userEvent.click(within(card).getByRole('button', { name: '이 코드로 확인' }));
    expect(await within(card).findByText('추가 인증 통과 뒤 허용 · 480건 · HTTP 200')).toBeInTheDocument();
    expect(posts.map((post) => [post.path, post.body])).toEqual([
      ['/api/live/runs/current/code', {}],
      ['/api/live/runs/current/answer', { code: '482913' }],
    ]);
  });

  it('cancels, and offers the way back when the time runs out (ST-12)', async () => {
    const with_ = (stage: string) =>
      liveView({
        scenario: 'S13T',
        status: 'CHALLENGE',
        challenge: {
          stage,
          code: null,
          secondsLeft: 0,
          attempts: 0,
          error: null,
          cause: null,
          codeRequestedMs: null,
          verifiedMs: null,
          reissueSentMs: null,
          reissueDoneMs: null,
          reissueStatus: null,
        } as never,
      });
    serve({ '/api/live/runs/current': with_('CANCELLED') });
    const first = flow('/simulate/person/S13T/live');
    expect(await screen.findByText('추가 인증을 취소했습니다. 요청은 멈춰 있습니다.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '다시 확인' })).toBeInTheDocument();
    first.unmount();
    serve({ '/api/live/runs/current': with_('EXPIRED') });
    flow('/simulate/person/S13T/live');
    expect(await screen.findByText('확인 시간이 지났습니다.')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '같은 시나리오 다시 실행' }));
    expect(screen.getByTestId('where')).toHaveTextContent('/simulate/person/S13T/review');
  });

  it('walks the account owner through the release of a block (ST-15)', async () => {
    const release = (stage: string, extra: Record<string, unknown> = {}) =>
      liveView({
        scenario: 'S13T',
        status: 'BLOCKED',
        release: {
          stage,
          code: null,
          secondsLeft: 100,
          attempts: 0,
          error: null,
          cause: null,
          reason: null,
          block: {
            id: 1,
            username: 'eng-k',
            status: 'BLOCKED',
            reasoning: 'Unfamiliar device and bulk export.',
            blockedAt: null,
            unblockReason: 'Working on HX-310',
            mfaVerified: true,
            unblockRequestedAt: null,
          },
          approverName: 'Security admin S',
          codeRequestedMs: null,
          verifiedMs: null,
          requestedMs: null,
          approvedMs: null,
          reissueSentMs: null,
          reissueDoneMs: null,
          reissueStatus: null,
          reissueOutcome: null,
          ...extra,
        } as never,
      });
    const posts = serve(
      { '/api/live/runs/current': release('VERIFIED') },
      {
        '/api/live/runs/current/release-request': { status: 200, body: release('REQUESTED') },
        '/api/live/runs/current/release-approve': {
          status: 200,
          body: release('DONE', { reissueDeliveredItems: 480, reissueStatus: 200 }),
        },
      },
    );
    flow('/simulate/person/S13T/live');
    const card = await screen.findByRole('region', { name: '차단 해제' });
    expect(within(card).getByRole('textbox', { name: '해제 요청 사유' })).toHaveValue(
      '정상 업무 중입니다. 추가 인증을 마치고 해제를 요청합니다.',
    );
    await userEvent.click(within(card).getByRole('button', { name: '해제 요청 보내기' }));
    expect(await within(card).findByText('Unfamiliar device and bulk export.')).toBeInTheDocument();
    await userEvent.click(within(card).getByRole('button', { name: '보안 담당자로 승인' }));
    expect(await within(card).findByText('승인 뒤 원래 요청 480건 · HTTP 200')).toBeInTheDocument();
    expect(posts.map((post) => post.path)).toEqual([
      '/api/live/runs/current/release-request',
      '/api/live/runs/current/release-approve',
    ]);
  });

  it('folds the measured times of a passed step-up under its result (P-8, 2-2)', async () => {
    serve({
      '/api/live/runs/current': liveView({
        scenario: 'S13T',
        status: 'CHALLENGE',
        challenge: {
          stage: 'DONE',
          code: null,
          secondsLeft: 0,
          attempts: 0,
          error: null,
          cause: null,
          codeRequestedMs: 1200,
          verifiedMs: 9800,
          reissueSentMs: 9900,
          reissueDoneMs: 10400,
          reissueStatus: 200,
          reissueOutcome: 'DELIVERED',
          reissueDeliveredItems: 480,
        },
      }),
    });
    flow('/simulate/person/S13T/live');
    const card = await screen.findByRole('region', { name: '추가 인증 요구' });
    expect(within(card).getByText('추가 인증 통과 뒤 허용 · 480건 · HTTP 200')).toBeInTheDocument();
    const times = within(card).getByText('자세히 · 추가 인증 요구 뒤 경과').closest('details') as HTMLElement;
    expect(valueOf(times, '코드 요청')).toHaveTextContent('1.2초');
    expect(valueOf(times, '코드 확인')).toHaveTextContent('9.8초');
    expect(valueOf(times, '원래 요청 재전송')).toHaveTextContent('9.9초');
    expect(valueOf(times, '재전송 응답 도착')).toHaveTextContent('10.4초');
    expect(valueOf(times, '재전송 결과')).toHaveTextContent('DELIVERED · HTTP 200');
  });

  it('shows the time left on the release code (P-8, 2-2)', async () => {
    serve({
      '/api/live/runs/current': liveView({
        scenario: 'S13T',
        status: 'BLOCKED',
        release: {
          stage: 'CODE_SHOWN',
          code: '731044',
          secondsLeft: 87,
          attempts: 0,
          error: null,
          cause: null,
          reason: null,
          block: null,
          approverName: null,
          codeRequestedMs: 300,
          verifiedMs: null,
          requestedMs: null,
          approvedMs: null,
          reissueSentMs: null,
          reissueDoneMs: null,
          reissueStatus: null,
          reissueOutcome: null,
          reissueDeliveredItems: null,
        },
      }),
    });
    flow('/simulate/person/S13T/live');
    const card = await screen.findByRole('region', { name: '차단 해제' });
    expect(within(card).getByRole('timer')).toHaveTextContent('87초 남음');
    expect(within(card).getByTestId('inbox-code')).toHaveTextContent('731044');
  });

  it('keeps the request sent again after a stored step-up under its request (P-8, 5-2)', async () => {
    const run = 'run-4f4e198f551f';
    serve({
      '/api/journey': journeyWith([{ scenarioKey: 'S16', runId: run }]),
      [`/api/runs/${run}/steps/1/result`]: resultInsider2,
      [`/api/runs/${run}/steps/2/result`]: resultInsider2,
      [`/api/runs/${run}/steps/3/result`]: resultInsider2,
      [`/api/runs/${run}/steps/2/anatomy`]: {
        ...anatomyInsider2,
        recovery: { challenge: passedCheck(2, 1), release: null },
      },
    });
    flow('/simulate/person/S16/live');
    const second = await screen.findByRole('region', { name: '요청 2의 응답' });
    expect(await within(second).findByText('추가 인증 통과 뒤 허용 · 1건 · HTTP 200')).toBeInTheDocument();
    const first = screen.getByRole('region', { name: '요청 1의 응답' });
    expect(within(first).queryByText(/추가 인증 통과 뒤 허용/)).toBeNull();
  });

  it('ends the step-up after three wrong codes and offers the way back (ST-11)', async () => {
    serve({
      '/api/live/runs/current': liveView({
        scenario: 'S13T',
        status: 'CHALLENGE',
        challenge: {
          stage: 'FAILED',
          code: null,
          secondsLeft: 0,
          attempts: 3,
          error: 'WRONG_CODE',
          cause: 'WRONG_CODE_LIMIT',
          codeRequestedMs: null,
          verifiedMs: null,
          reissueSentMs: null,
          reissueDoneMs: null,
          reissueStatus: null,
        } as never,
      }),
    });
    flow('/simulate/person/S13T/live');
    expect(
      await screen.findByText('업무를 이어 가지 못했습니다. 코드를 3회 잘못 입력했습니다.'),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '같은 시나리오 다시 실행' })).toBeInTheDocument();
  });

  it('asks for the release at once for the compromised account, whose block stays (ST-14)', async () => {
    const blocked = liveView({
      status: 'BLOCKED',
      release: {
        stage: 'BLOCKED',
        code: null,
        secondsLeft: 100,
        attempts: 0,
        error: null,
        cause: null,
      } as never,
    });
    const posts = serve(
      { '/api/live/runs/current': blocked },
      {
        '/api/live/runs/current/release-start': {
          status: 200,
          body: { ...blocked, release: { ...blocked.release, stage: 'NO_MAILBOX' } },
        },
      },
    );
    flow('/simulate/person/S13/live');
    expect(
      await screen.findByText('차단 해제 코드도 계정 주인의 메일함으로 가서, 차단은 그대로입니다.'),
    ).toBeInTheDocument();
    expect(posts.map((post) => post.path)).toEqual(['/api/live/runs/current/release-start']);
  });

  it('waits for the record to be stored before the result opens (ST-20) and names a missing decision (ST-17)', async () => {
    serve({
      '/api/live/runs/current': liveView({
        status: 'RUNNING',
        runId: ATTACKER_RUN,
        steps: [
          {
            stepNo: 1,
            operation: 'EXPORT',
            layers: {
              ...RULES_ANSWERED,
              D: { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 480, elapsedMs: 9000 },
            },
          },
        ],
      }),
      '/api/live/runs/current/analysis?step=1': {
        ...ANALYSIS_RUNNING,
        stages: [
          ...ANALYSIS_RUNNING.stages,
          {
            type: 'ANALYSIS_ERROR',
            atMs: 9000,
            action: null,
            layer: null,
            riskScore: null,
            confidence: null,
            elapsedMs: null,
            mitre: null,
          },
        ],
        decision: {
          finalAction: 'ALLOW',
          proposedAction: null,
          unresolved: true,
          riskScore: null,
          confidence: null,
          applied: 'BEFORE_RESPONSE',
          reason: null,
          adverseLabels: [],
          adverseMet: 0,
          adverseChecked: 0,
          totalAnalysisMs: null,
          modelCalls: 1,
          promptTokens: 0,
          completionTokens: 0,
        },
        decisionWait: null,
      },
    });
    flow('/simulate/person/S13/live');
    const table = await screen.findByRole('table', { name: '5개 보안 통제의 응답' });
    expect(await within(table).findByText('판정 없음')).toBeInTheDocument();
    expect(screen.getByText('분석 오류 · 판정 없음')).toBeInTheDocument();
    expect(screen.getAllByText('실행 기록 저장 중').length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: '결과 · 판정 근거' })).toHaveAccessibleDescription(
      '실행 기록 저장 중',
    );
  });

  it('follows the last request with a decision of its own in a case of several requests', async () => {
    const one = { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 1, elapsedMs: 20 } as const;
    const rules = { A: one, B: one, C1: one, C2: one };
    serve({
      '/api/live/runs/current': liveView({
        scenario: 'S16',
        status: 'RUNNING',
        steps: [
          { stepNo: 1, operation: 'DOCUMENT_DOWNLOAD', layers: { ...rules, D: one } },
          { stepNo: 2, operation: 'DOCUMENT_DOWNLOAD', layers: { ...rules, D: one } },
          {
            stepNo: 3,
            operation: 'DOCUMENT_DOWNLOAD',
            layers: {
              ...rules,
              D: {
                outcome: 'STOPPED',
                httpStatus: 403,
                deliveredItems: 0,
                elapsedMs: 10,
                ruleId: 'ACCOUNT_BLOCKED',
              },
            },
          },
        ],
      }),
      '/api/live/runs/current/analysis?step=2': ANALYSIS_RUNNING,
    });
    flow('/simulate/person/S16/live');
    expect(await screen.findByText('요청 2에서 Contexa가 확인한 것')).toBeInTheDocument();
    expect(screen.getAllByRole('table', { name: '5개 보안 통제의 응답' })).toHaveLength(3);
  });

  it('names a request refused by an earlier decision (ST-18)', async () => {
    serve({
      '/api/live/runs/current': liveView({
        status: 'COMPLETED',
        runId: ATTACKER_RUN,
        steps: [
          {
            stepNo: 1,
            operation: 'EXPORT',
            layers: {
              ...RULES_ANSWERED,
              D: {
                outcome: 'STOPPED',
                httpStatus: 403,
                deliveredItems: 0,
                elapsedMs: 20,
                ruleId: 'ACCOUNT_BLOCKED',
              },
            },
          },
        ],
      }),
    });
    flow('/simulate/person/S13/live');
    expect(await screen.findByText('앞선 판정으로 거절')).toBeInTheDocument();
  });
});

describe('step 4: the result and the comparison', () => {
  it('titles the result screen when the visitor has no run of the scenario yet (기획안 11절 2-3)', async () => {
    serve();
    flow('/simulate/person/S13/result');
    expect(await screen.findByRole('heading', { level: 1, name: '결과 · 판정 근거' })).toBeInTheDocument();
    expect(screen.getByText('이 시나리오의 실행 기록이 아직 없습니다.')).toBeInTheDocument();
  });

  it('states the conclusion, the exports and the evidence from the server score of the run', async () => {
    serve();
    flow(`/simulate/person/S13/result?run=${ATTACKER_RUN}`);
    expect(
      await screen.findByRole('heading', { level: 1, name: '추가 인증을 요구해 반출 480건을 막았습니다' }),
    ).toBeInTheDocument();
    expect(screen.getByText(/기존 보안 통제 4개는 같은 요청을 모두 허용했습니다\./)).toBeInTheDocument();
    const exports = screen.getByRole('region', { name: '반출 건수 비교' });
    expect(within(exports).getAllByText('미탐')).toHaveLength(4);
    expect(within(exports).getByText('적중')).toBeInTheDocument();
    const latency = screen.getByRole('region', { name: '판정 시간과 적용 방식' });
    expect(within(latency).getByText(/0\.029초 ~ 0\.058초/)).toBeInTheDocument();
    expect(within(latency).getByText(/판정 8\.7초 · 응답 8\.7초/)).toBeInTheDocument();
    const evidence = screen.getByRole('region', { name: '판정 근거' });
    expect(await within(evidence).findByText('요청한 사람이 이 대상의 담당자입니다.')).toBeInTheDocument();
    expect(within(evidence).getByText('건수가 행위 기준선의 범위를 넘습니다.')).toBeInTheDocument();
    expect(within(evidence).getByText('원문')).toBeInTheDocument();
    expect(within(evidence).getByText('위험도 0.35 · 확신도 0.78')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'S13T 실행' })).toHaveAttribute(
      'href',
      '/simulate/person/S13T/review',
    );
  });

  it('folds what each control answered, as the run stored it, under the exported items (P-8, 2-3)', async () => {
    const response = (control: string, httpStatus: number, deliveredItems: number, excerpt: string) => ({
      control,
      method: 'POST',
      path: '/api/projects/HX-310/exports',
      sentAt: '2026-10-20T12:31:37.512Z',
      httpStatus,
      deliveredItems,
      elapsedMs: 50,
      excerpt,
    });
    serve({
      [`/api/runs/${ATTACKER_RUN}/steps/1/responses`]: [
        response('A', 200, 480, '{"exportId":"EXP-1","items":480}'),
        response('D', 401, 0, '{"error":"MFA_CHALLENGE_REQUIRED"}'),
      ],
    });
    flow(`/simulate/person/S13/result?run=${ATTACKER_RUN}`);
    const exports = await screen.findByRole('region', { name: '반출 건수 비교' });
    const answers = (await within(exports).findByText('자세히 · 통제별 응답 원문')).closest(
      'details',
    ) as HTMLElement;
    expect(within(answers).getAllByText('POST /api/projects/HX-310/exports')).toHaveLength(2);
    expect(within(answers).getAllByText('보낸 시각 2026-10-20 12:31 세계 표준시')).toHaveLength(2);
    expect(within(answers).getByText('HTTP 401')).toBeInTheDocument();
    expect(within(answers).getByLabelText('Contexa 응답 원문')).toHaveTextContent(
      '{"error":"MFA_CHALLENGE_REQUIRED"}',
    );
    expect(within(answers).getByLabelText('웹 방화벽 응답 원문')).toHaveTextContent('"items":480');
    // The compromised account never passed its step-up: no stored check record is shown.
    expect(screen.queryByText('자세히 · 저장된 추가 인증 기록')).toBeNull();
  });

  it('keeps the stored step-up record of a request that passed it (P-8, 4-4)', async () => {
    serve({
      [`/api/runs/${OWNER_RUN}/steps/1/anatomy`]: {
        ...anatomyOwner,
        recovery: { challenge: passedCheck(1, 480), release: null },
      },
    });
    flow(`/simulate/person/S13T/result?run=${OWNER_RUN}`);
    const record = (await screen.findByText('자세히 · 저장된 추가 인증 기록')).closest('details') as HTMLElement;
    expect(valueOf(record, '추가 인증 요구')).toHaveTextContent('2026-10-20 12:31 세계 표준시');
    expect(valueOf(record, '코드 받기')).toHaveTextContent('2026-10-20 12:31 세계 표준시');
    expect(valueOf(record, '코드 확인')).toHaveTextContent('2026-10-20 12:32 세계 표준시');
    expect(valueOf(record, '원래 요청 재시도')).toHaveTextContent('2026-10-20 12:32 세계 표준시');
    expect(valueOf(record, '재전송 결과')).toHaveTextContent('추가 인증 통과 뒤 허용 · 480건 · HTTP 200');
  });

  it('rests the insider result on the request the engine blocked (run-4f4e198f551f, request 2 of 3)', async () => {
    const run = 'run-4f4e198f551f';
    serve({
      [`/api/runs/${run}/score`]: scoreInsider,
      [`/api/runs/${run}/steps/2/result`]: resultInsider2,
      [`/api/runs/${run}/steps/2/anatomy`]: anatomyInsider2,
      [`/api/runs/${run}/steps/2/quality`]: qualityInsider2,
      [`/api/runs/${run}/steps/2/facts`]: factsInsider2,
    });
    flow(`/simulate/person/S16/result?run=${run}`);
    expect(
      await screen.findByRole('heading', { level: 1, name: '일부가 반출된 뒤 차단했습니다(반출 2건)' }),
    ).toBeInTheDocument();
    expect(screen.getByText('요청 2 / 3')).toBeInTheDocument();
    const side = screen.getByText('판정한 요청').closest('dl') as HTMLElement;
    expect(within(side).getByText('차단')).toBeInTheDocument();
    expect(within(side).getByText(/24\.8초 · 다음 요청부터 적용/)).toBeInTheDocument();
    const evidence = screen.getByRole('region', { name: '판정 근거' });
    expect(await within(evidence).findByText('DATA_NATURE_MISMATCH')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: '반출 건수 비교' })).toHaveTextContent('일부 반출 뒤 차단');
  });

  it('opens "same request, different decision" once both runs exist (F-7)', async () => {
    serve({
      '/api/journey': journeyWith([
        { scenarioKey: 'S13', runId: ATTACKER_RUN },
        { scenarioKey: 'S13T', runId: OWNER_RUN },
      ]),
      // The portal's InputComparison of the two fixtures' anatomies (anatomy-attacker / anatomy-owner): one line.
      [`/api/runs/${OWNER_RUN}/steps/1/input-changes?against=${ATTACKER_RUN}`]: [
        { key: 'dim.device', before: 'Safari/18 on MAC · false', now: 'Edge/140 on WINDOWS · true' },
      ],
    });
    flow('/simulate/person/S13/result?tab=compare');
    expect(
      await screen.findByRole('heading', { level: 1, name: '같은 요청, 다른 판정' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: '같은 요청, 다른 판정' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    const table = await screen.findByRole('table', { name: '두 실행의 요청 사실' });
    const changed = within(table)
      .getAllByRole('row')
      .filter((row) => row.hasAttribute('data-diff'))
      .map((row) => within(row).getByRole('rowheader').textContent);
    expect(changed).toEqual(['단말', '기준선 이탈']);
    // P-8 (4-3): the portal's line-by-line comparison of the engine input, folded under the facts.
    const inputs = (await screen.findByText('자세히 · 엔진 입력에서 다른 줄 1개')).closest('details') as HTMLElement;
    expect(
      within(within(inputs).getByRole('table', { name: '엔진 입력' }))
        .getAllByRole('row')
        .slice(1)
        .map((row) => row.textContent),
    ).toEqual(['단말Safari/18 on MAC · 기준선 이탈Edge/140 on WINDOWS · 기준선 안']);
    expect(screen.getByText('규칙 기반 통제는 두 요청을 구분하지 못했습니다')).toBeInTheDocument();
    const learning = screen.getByRole('region', { name: '기준선 학습' });
    expect(within(learning).getByText('49 → 49')).toBeInTheDocument();
    expect(within(learning).getByText('49 → 50')).toBeInTheDocument();
    expect(within(learning).getByText('+1 학습')).toBeInTheDocument();
    act(() => {
      fireEvent.click(screen.getByRole('tab', { name: 'S13T 결과 · 판정 근거' }));
    });
    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: '정상 업무로 판정해 480건을 그대로 처리했습니다',
      }),
    ).toBeInTheDocument();
  });
});
