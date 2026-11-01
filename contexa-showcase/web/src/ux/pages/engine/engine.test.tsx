import { screen, waitFor, within } from '@testing-library/react';
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
      await screen.findByRole('heading', { name: `엔지니어 K의 행위 기준선` }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText('시간대별 학습 요청').querySelectorAll('li')).toHaveLength(24);
    expect(screen.getByText(baseline.learned.networks.join(', '))).toBeInTheDocument();
  });
});
