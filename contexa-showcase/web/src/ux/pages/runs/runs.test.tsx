import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import anatomyAttacker from '../../test/fixtures/anatomy-attacker.test.json';
import benchmarkRuns from '../../test/fixtures/benchmark-runs.test.json';
import exchangesAttacker from '../../test/fixtures/exchanges-attacker.test.json';
import factsAttacker from '../../test/fixtures/facts-attacker.test.json';
import hook from '../../test/fixtures/hook.test.json';
import liveConfig from '../../test/fixtures/live-config.test.json';
import pairs from '../../test/fixtures/pairs.test.json';
import qualityAttacker from '../../test/fixtures/quality-attacker.test.json';
import receivedAttacker from '../../test/fixtures/received-attacker.test.json';
import replayA3 from '../../test/fixtures/replay-A3.test.json';
import resultAttacker from '../../test/fixtures/result-attacker.test.json';
import scoreAttacker from '../../test/fixtures/score-attacker.test.json';
import scoreOwner from '../../test/fixtures/score-owner.test.json';
import { renderAt, stubPortal, type PortalStub } from '../../test/portal';
import { DRAWER_QUERY } from '../../useMedia';
import RunDetailPage from './RunDetailPage';
import RunsPage from './RunsPage';

const ATTACKER = hook.attacker.runId;
const OWNER = hook.owner.runId;
const base = (run: string) => `/api/runs/${run}`;

/** The portal's real answers (src/ux/test/fixtures, 2026-10-31) by the paths the log and the details read. */
const BASE: Record<string, unknown> = {
  '/api/visitor': { predictions: {}, csrfHeader: 'X-XSRF-TOKEN' },
  '/api/journey': {
    state: { route: 'DEFAULT', act: 0, step: 'start', differences: [], predictions: {} },
    runs: [],
    predictions: [],
  },
  '/api/live/config': liveConfig,
  '/api/hook': hook,
  '/api/pairs': pairs,
  '/api/replays/A3': replayA3,
  '/api/benchmark/runs': benchmarkRuns,
  [`${base(ATTACKER)}/score`]: scoreAttacker,
  [`${base(OWNER)}/score`]: scoreOwner,
  [`${base(ATTACKER)}/steps/1/anatomy`]: anatomyAttacker,
  [`${base(ATTACKER)}/steps/1/result`]: resultAttacker,
  [`${base(ATTACKER)}/steps/1/received`]: receivedAttacker,
  [`${base(ATTACKER)}/steps/1/quality`]: qualityAttacker,
  [`${base(ATTACKER)}/steps/1/facts`]: factsAttacker,
  [`${base(ATTACKER)}/steps/1/exchanges`]: exchangesAttacker,
};

function serve(extra: PortalStub['get'] = {}) {
  return stubPortal({ get: { ...BASE, ...extra } });
}

function open(address: string) {
  return renderAt(
    address,
    <Routes>
      <Route path="/runs" element={<RunsPage />} />
      <Route path="/runs/:runId" element={<RunDetailPage />} />
    </Routes>,
  );
}

/** Every run the log should hold: the public pair, the recorded replay's scenes and the measured runs, once each. */
const EXPECTED = new Set([ATTACKER, OWNER, ...replayA3.scenes.map((scene) => scene.runId), ...benchmarkRuns.runs.map((run) => run.runId)]);

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the decision log', () => {
  it('holds the public recorded runs and the measured runs, each run once, with its source (DEC-40)', async () => {
    serve();
    open('/runs');
    const table = await screen.findByRole('table', { name: '판정 이력' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(Math.min(10, EXPECTED.size) + 1));
    expect(screen.getByText(`전체 ${EXPECTED.size}건 중 1–${Math.min(10, EXPECTED.size)}`)).toBeInTheDocument();
    expect(within(table).getAllByText('공개 녹화').length).toBeGreaterThan(0);
    expect(within(table).getAllByText('측정').length).toBeGreaterThan(0);
  });

  it('filters by source, and says when a filter leaves no row (ST-41)', async () => {
    serve();
    const first = open('/runs?source=measured');
    const table = await screen.findByRole('table', { name: '판정 이력' });
    // A measured run that is also a public recording keeps the public source (DEC-40).
    const publicRuns = new Set([ATTACKER, OWNER, ...replayA3.scenes.map((scene) => scene.runId)]);
    const measuredOnly = benchmarkRuns.runs.filter((run) => !publicRuns.has(run.runId)).length;
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(measuredOnly + 1));
    expect(within(table).queryByText('공개 녹화')).not.toBeInTheDocument();
    first.unmount();
    serve();
    open('/runs?q=no-such-run');
    expect(await screen.findByText('조건에 맞는 기록이 없습니다.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '필터 지우기' })).toHaveAttribute('href', '/runs');
  });

  it('keeps the other sources when one cannot be read (ST-40)', async () => {
    serve({ '/api/benchmark/runs': 500 });
    open('/runs');
    expect(await screen.findByText('일부 기록을 불러오지 못했습니다(측정). 나머지 기록은 그대로 보입니다.')).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: '판정 이력' });
    expect(within(table).getAllByText('공개 녹화').length).toBeGreaterThan(0);
  });

  it('opens the chosen run beside the list with its decision and the five controls\' exports', async () => {
    serve();
    open(`/runs?run=${ATTACKER}`);
    const panel = await screen.findByRole('complementary');
    expect(await within(panel).findByText(/위험도 0\.\d\d · 확신도/)).toBeInTheDocument();
    const exported = scoreAttacker.business.A.exposedItems;
    expect(within(panel).getAllByText(`${exported}건 반출`).length).toBe(4);
    expect(within(panel).getByRole('link', { name: '상세 보기' })).toHaveAttribute('href', `/runs/${ATTACKER}`);
  });

  it('keeps three columns beside the chosen run, the decision and the result in one cell', async () => {
    serve();
    open(`/runs?run=${ATTACKER}`);
    const table = await screen.findByRole('table', { name: '판정 이력' });
    expect(within(table).getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual([
      '시각(세계 표준시)',
      '시나리오',
      'Contexa 판정 · 결과',
    ]);
  });

  it('holds the chosen run in a drawer below 1024 wide, with one head and one close button', async () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query === DRAWER_QUERY,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }));
    serve();
    open(`/runs?run=${ATTACKER}`);
    const drawer = await screen.findByRole('dialog');
    expect(within(drawer).getAllByRole('button', { name: '닫기' })).toHaveLength(1);
    expect(within(drawer).getByRole('heading', { level: 2 })).toHaveTextContent(ATTACKER);
    expect(within(drawer).getByRole('link', { name: '상세 보기' })).toHaveAttribute('href', `/runs/${ATTACKER}`);
    expect(await within(drawer).findByText(/위험도 0\.\d\d · 확신도/)).toBeInTheDocument();
  });
});

describe('the decision details', () => {
  it('heads the run with its truth, grade and decision, and sums the request up', async () => {
    serve();
    open(`/runs/${ATTACKER}`);
    expect(await screen.findByRole('heading', { level: 1, name: ATTACKER })).toBeInTheDocument();
    expect(screen.getAllByText('정답: 위협').length).toBeGreaterThan(0);
    expect(screen.getByLabelText('요청 요약')).toHaveTextContent(anatomyAttacker.context.resource.requestPath);
    const summary = screen.getByRole('region', { name: '판정 요약' });
    expect(within(summary).getByText(/학습 요청 \d+ → \d+/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '같은 요청 다시 실행' })).toHaveAttribute('href', '/simulate/person/S13/review');
  });

  it('says a record that does not exist apart from a read that failed (ST-43)', async () => {
    serve({ [`${base('run-none')}/steps/1/anatomy`]: 404 });
    const first = open('/runs/run-none');
    expect(await screen.findByText('이 실행 기록이 없습니다. 실행 ID를 확인합니다.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '다시 시도' })).not.toBeInTheDocument();
    first.unmount();
    serve({ [`${base('run-none')}/steps/1/anatomy`]: 500 });
    open('/runs/run-none');
    expect(await screen.findByText('기록을 불러오지 못했습니다.')).toBeInTheDocument();
  });

  it('says why a request has no decision of its own: an earlier decision (ST-44)', async () => {
    const prior = {
      ...anatomyAttacker,
      interpretation: {
        ...anatomyAttacker.interpretation,
        recorded: { ...anatomyAttacker.interpretation.recorded, finalAction: null, unresolved: false, failureType: null },
      },
      truth: { ...anatomyAttacker.truth, verdict: { ...anatomyAttacker.truth.verdict, source: 'PRIOR_DECISION' } },
    };
    serve({ [`${base(ATTACKER)}/steps/1/anatomy`]: prior });
    open(`/runs/${ATTACKER}`);
    expect(await screen.findByText(/앞선 판정이 이미 막고 있어 앱이 거절했습니다/)).toBeInTheDocument();
  });

  it('shows the inspection as it stands, unverifiable checks included (DEC-43)', async () => {
    serve();
    open(`/runs/${ATTACKER}?tab=integrity`);
    const inspection = await screen.findByRole('region', { name: '공식 검사' });
    expect(await within(inspection).findByText('불완전 · 확인 불가 항목 있음')).toBeInTheDocument();
    const checks = qualityAttacker.inspection.checks;
    expect(within(inspection).getAllByRole('row')).toHaveLength(checks.length + 1);
    expect(screen.getByRole('button', { name: '기록 JSON 내려받기' })).toBeInTheDocument();
  });

  it('quotes a fact once though several codes cite it, and weighs the hypotheses', async () => {
    serve();
    open(`/runs/${ATTACKER}?tab=evidence`);
    const cited = await screen.findByRole('region', { name: '인용 사실과 판정 근거' });
    const codes = qualityAttacker.reasonCodes;
    await waitFor(() => expect(within(cited).getAllByRole('listitem').length).toBeGreaterThanOrEqual(codes.length));
    const repeated = codes.filter((code, index) => codes.findIndex((other) => other.fact === code.fact) !== index).length;
    expect(within(cited).queryAllByText(/와 같은 사실$/)).toHaveLength(repeated);
    expect(screen.getByRole('region', { name: '가설 평가' })).toBeInTheDocument();
  });

  it('shows the model\'s answer as it was received', async () => {
    serve();
    open(`/runs/${ATTACKER}?tab=response`);
    expect(await screen.findByRole('heading', { name: '모델 호출 1' })).toBeInTheDocument();
    expect(screen.getByLabelText('모델의 답(원문)')).toHaveTextContent(exchangesAttacker.calls[0]?.answer?.slice(0, 20) ?? '');
  });

  it('moves between the requests of a run of several, keeping the tab (ST-45)', async () => {
    serve({ [`${base(ATTACKER)}/score`]: { ...scoreAttacker, executedSteps: 3 } });
    open(`/runs/${ATTACKER}?tab=controls&step=1`);
    const steps = await screen.findByRole('navigation', { name: '요청 고르기' });
    await userEvent.click(within(steps).getByRole('link', { name: '요청 2' }));
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('tab=controls'));
    expect(screen.getByTestId('where')).toHaveTextContent('step=2');
  });
});
