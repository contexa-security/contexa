import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import anatomiesA6T from '../../test/fixtures/anatomies-A6T.test.json';
import anatomyAttacker from '../../test/fixtures/anatomy-attacker.test.json';
import baseline from '../../test/fixtures/baseline-eng-k.test.json';
import engineActions from '../../test/fixtures/engine-actions.test.json';
import hook from '../../test/fixtures/hook.test.json';
import labOptions from '../../test/fixtures/lab-options.test.json';
import liveConfig from '../../test/fixtures/live-config.test.json';
import measuredA3 from '../../test/fixtures/measured-A3.test.json';
import measuredA3A from '../../test/fixtures/measured-A3A.test.json';
import measuredA6T from '../../test/fixtures/measured-A6T.test.json';
import qualityAttacker from '../../test/fixtures/quality-attacker.test.json';
import receivedAttacker from '../../test/fixtures/received-attacker.test.json';
import scoreAttacker from '../../test/fixtures/score-attacker.test.json';
import stats from '../../test/fixtures/stats.test.json';
import { renderAt, stubPortal, type PortalStub } from '../../test/portal';
import EnginePage from './EnginePage';

const RUN = hook.attacker.runId;
const run = (path: string) => `/api/runs/${RUN}${path}`;

const BASE: Record<string, unknown> = {
  '/api/visitor': { predictions: {}, csrfHeader: 'X-XSRF-TOKEN' },
  '/api/journey': {
    state: { route: 'DEFAULT', act: 0, step: 'start', differences: [], predictions: {} },
    runs: [],
    predictions: [],
  },
  '/api/live/config': liveConfig,
  '/api/lab/options': labOptions,
  '/api/hook': hook,
  '/api/stats': stats,
  '/api/engine/actions': engineActions,
  '/api/live/baseline/eng-k': baseline,
  '/api/cases/A3/measured': measuredA3,
  '/api/cases/A3A/measured': measuredA3A,
  '/api/cases/A6T/measured': measuredA6T,
  [`/api/runs/${anatomiesA6T.runId}/steps/1/anatomy`]: anatomiesA6T.steps[0],
  [run('/score')]: scoreAttacker,
  [run('/steps/1/anatomy')]: anatomyAttacker,
  [run('/steps/1/received')]: receivedAttacker,
  [run('/steps/1/quality')]: qualityAttacker,
};

function serve(extra: PortalStub['get'] = {}) {
  return stubPortal({ get: { ...BASE, ...extra } });
}

/** The case list with the learned normal-work case and its employee, in the shapes the portal gives (lab options). */
const [ENGINEER] = labOptions.employees;
const [S13] = labOptions.cases;
const OPTIONS_WITH_A6T = {
  ...labOptions,
  employees: [...labOptions.employees, { ...ENGINEER, key: 'adm-a', displayName: 'Administrator A', role: 'ADMIN' }],
  cases: [...labOptions.cases, { ...S13, key: 'A6T', conditions: { ...S13?.conditions, employee: 'adm-a' } }],
};

/** The same person's normal work measured both ways, in the shape of a measured case. */
const measuredNormal = (caseKey: string, responseMs: { min: number; max: number }) => ({
  ...measuredA3,
  caseKey,
  results: { PASSED: 2 },
  responseMs,
});

/** A stored release as the run's anatomy carries it (run_release, times in UTC). */
const RELEASE = {
  released: true,
  reason: null,
  blocked_at: '2026-10-19T07:20:44Z',
  code_requested_at: '2026-10-19T07:20:44Z',
  verified_at: '2026-10-19T07:20:46Z',
  requested_at: '2026-10-19T07:20:48Z',
  approved_at: '2026-10-19T07:21:50Z',
  reissue_sent_at: null,
  reissue_status: null,
  reissue_outcome: null,
  reissue_delivered: null,
  block_record: null,
};

function open(address: string) {
  return renderAt(
    address,
    <Routes>
      <Route path="/engine" element={<EnginePage />} />
    </Routes>,
  );
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the AI decision engine', () => {
  it('walks the seven stages with the public recording\'s own values (DEC-45, ST-50)', async () => {
    serve();
    open('/engine');
    expect(await screen.findByText('기준 실행 · 공개 녹화 실행')).toBeInTheDocument();
    const figures = anatomyAttacker.figures;
    expect(
      await screen.findByText(`학습 요청 ${figures.baselineBefore}건 · 최근 7일 ${figures.workProfileObservations}건과 비교`),
    ).toBeInTheDocument();
    const lines = anatomyAttacker.promptLines;
    expect(screen.getByText(`시스템 규칙 ${lines.system}줄 + 상황 ${lines.user}줄 = ${lines.total}줄`)).toBeInTheDocument();
    expect(screen.getAllByRole('listitem').filter((item) => item.textContent?.match(/^[1-7]/)).length).toBeGreaterThanOrEqual(7);
  });

  it('sets the run against a measured run of normal work that was learned, and seals with every check counted', async () => {
    serve();
    open('/engine');
    const learning = await screen.findByRole('region', { name: '기준선 학습 범위' });
    const other = anatomiesA6T.steps[0]?.figures;
    await waitFor(() =>
      expect(learning).toHaveTextContent(`${other?.baselineBefore} → ${other?.baselineAfter}`),
    );
    const seal = screen.getByRole('region', { name: '무결성 봉인' });
    const checks = qualityAttacker.inspection.checks;
    const sum = (key: 'matched' | 'mismatched' | 'unverifiable') => checks.reduce((total, check) => total + check[key], 0);
    await waitFor(() =>
      expect(seal).toHaveTextContent(`일치 ${sum('matched')} · 불일치 ${sum('mismatched')} · 확인 불가 ${sum('unverifiable')}`),
    );
  });

  it('says how long each decision holds in the largest whole unit', async () => {
    serve();
    open('/engine');
    const follow = await screen.findByRole('region', { name: '판정별 후속 조치' });
    expect(await within(follow).findByText('HTTP 401 · 30분 유지')).toBeInTheDocument();
    expect(within(follow).getByText('HTTP 403 · 해제할 때까지 유지')).toBeInTheDocument();
  });

  it('follows the visitor\'s own latest account-takeover run when there is one', async () => {
    serve({
      '/api/journey': {
        state: { route: 'DEFAULT', act: 0, step: 'start', differences: [], predictions: {} },
        runs: [{ runId: 'run-own-1', scenarioKey: 'S13', classification: 'THREAT', status: 'COMPLETED', lab: false }],
        predictions: [],
      },
      '/api/runs/run-own-1/steps/1/anatomy': anatomyAttacker,
    });
    open('/engine');
    expect(await screen.findByText('기준 실행 · 내 최근 실행')).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: /공개 녹화 실행으로 보기/ })).toBeInTheDocument();
  });

  it('draws the baseline the account was taught', async () => {
    serve();
    open('/engine?tab=baseline');
    expect(
      await screen.findByRole('heading', { name: '학습된 행위 기준선(엔지니어 K)' }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText('시간대별 학습 요청').querySelectorAll('li')).toHaveLength(24);
    expect(screen.getByText('기준선 네트워크').nextElementSibling).toHaveTextContent(baseline.learned.networks.join(', '));
  });

  it('names the employee whose measured run of normal work the learning is set against (옛 3-1)', async () => {
    serve({ '/api/lab/options': OPTIONS_WITH_A6T });
    open('/engine');
    const learning = await screen.findByRole('region', { name: '기준선 학습 범위' });
    expect(await within(learning).findByText('비교 · 관리자 A의 정상 업무 측정 실행')).toBeInTheDocument();
  });

  it('sets the same person\'s normal work beside the export, each line with the results the server counted (옛 M-timing)', async () => {
    serve({
      '/api/cases/A3T/measured': measuredNormal('A3T', { min: 10200, max: 12500 }),
      '/api/cases/A3TA/measured': measuredNormal('A3TA', { min: 44, max: 44 }),
    });
    open('/engine');
    const timing = await screen.findByRole('region', { name: '판정 적용 시점: 동기 · 비동기' });
    const attack = await within(timing).findByRole('list', { name: '탈취된 계정의 반출' });
    expect(within(attack).getAllByRole('listitem')[0]).toHaveTextContent(`적중${measuredA3.results.STOPPED}회`);
    expect(within(attack).getAllByRole('listitem')[1]).toHaveTextContent(`일부 반출 뒤 차단${measuredA3A.results.PARTLY_STOPPED}회`);
    const normal = await within(timing).findByRole('list', { name: '정상 업무' });
    const [sync, async] = within(normal).getAllByRole('listitem');
    expect(sync).toHaveTextContent('응답 전 판정(동기)');
    expect(sync).toHaveTextContent('응답 10.2~12.5초');
    expect(sync).toHaveTextContent('정상 처리2회');
    expect(async).toHaveTextContent('응답 0.044초');
  });

  it('leaves the normal-work lines out while they are not measured', async () => {
    serve();
    open('/engine');
    const timing = await screen.findByRole('region', { name: '판정 적용 시점: 동기 · 비동기' });
    expect(await within(timing).findByRole('list', { name: '탈취된 계정의 반출' })).toBeInTheDocument();
    expect(within(timing).queryByRole('list', { name: '정상 업무' })).not.toBeInTheDocument();
  });

  it('opens the latest actual release: a forced block named, each stage at its time, and its run (옛 M-follow)', async () => {
    serve({
      '/api/follow/release': { runId: 'run-release', stepNo: 1, scenarioKey: 'A3T', forcedAction: 'BLOCK', approvedAt: null },
      '/api/runs/run-release/steps/1/anatomy': { ...anatomyAttacker, runId: 'run-release', recovery: { challenge: null, release: RELEASE } },
    });
    open('/engine');
    const follow = await screen.findByRole('region', { name: '판정별 후속 조치' });
    await userEvent.click(within(follow).getByText('최근 실제 해제 기록 자세히'));
    expect(await within(follow).findByText('시연용 강제 판정 · BLOCK')).toBeInTheDocument();
    const stages = within(follow).getByRole('list', { name: '해제 단계와 시각' });
    const rows = within(stages).getAllByRole('listitem');
    expect(rows).toHaveLength(6);
    expect(rows[0]).toHaveTextContent('차단2026-10-19 07:20 (세계 표준시)');
    expect(rows[4]).toHaveTextContent('관리자 승인2026-10-19 07:21 (세계 표준시)');
    expect(rows[5]).toHaveTextContent('원래 요청 다시 보냄—');
    expect(within(follow).getByRole('link', { name: 'run-release' })).toHaveAttribute('href', '/runs/run-release');
  });

  it('says when no block has been released yet', async () => {
    serve();
    open('/engine');
    const follow = await screen.findByRole('region', { name: '판정별 후속 조치' });
    await userEvent.click(within(follow).getByText('최근 실제 해제 기록 자세히'));
    expect(await within(follow).findByText('아직 해제까지 끝난 기록 없음')).toBeInTheDocument();
  });

  it('draws the office network, the projects taught, every learning request and the latest learning state (옛 M-learned)', async () => {
    serve();
    open('/engine?tab=baseline');
    await screen.findByRole('heading', { name: '학습된 행위 기준선(엔지니어 K)' });
    expect(screen.getByText('사무실 네트워크').nextElementSibling).toHaveTextContent(ENGINEER?.officeNetwork ?? '');
    const [project, count] = Object.entries(baseline.taught.projects)[0] ?? [];
    expect(screen.getByText('학습시킨 프로젝트').nextElementSibling).toHaveTextContent(`${project} ${count}건`);
    expect(
      screen.getByText(
        `보낸 학습 요청 ${baseline.sent}건 · 허용 ${baseline.allowed}건 · 기준선에 학습 ${baseline.learned.requests}건`,
      ),
    ).toBeInTheDocument();
    const table = screen.getByRole('table', { name: '보낸 학습 요청' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(baseline.requests.length);
    const first = baseline.requests[0];
    expect(rows[0]).toHaveTextContent(`${first?.no}2026-09-16 09:29${first?.path}—허용`);
    const hours = baseline.hours;
    expect(screen.getByText('개인 기준선 상태').nextElementSibling).toHaveTextContent(hours.personalBaselineStatus);
    expect(screen.getByText('업무 범위 상태').nextElementSibling).toHaveTextContent(
      `${hours.roleScopeState}업무 범위 학습이 아직 적어 이 상태만으로는 판정하지 않음`,
    );
    expect(screen.getByText('자주 본 시각').nextElementSibling).toHaveTextContent(
      hours.normalAccessHours.map((hour) => `${hour}시`).join(', '),
    );
    expect(screen.getByRole('link', { name: hours.runId })).toHaveAttribute('href', `/runs/${hours.runId}`);
  });
});
