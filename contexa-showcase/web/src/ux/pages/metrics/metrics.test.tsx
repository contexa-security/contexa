import { screen, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import type { StatsView } from '../../../api/types';
import stats from '../../test/fixtures/stats.test.json';
import { renderAt, stubPortal } from '../../test/portal';
import MetricsPage from './MetricsPage';
import { axisEnd, failedShare, operatorRuns } from './stats';

/** The portal's real answer (2026-10-31 16:49 UTC). */
const STATS = stats as unknown as StatsView;

function open(tab: string, answer: unknown = STATS) {
  stubPortal({ get: { '/api/stats': answer } });
  return renderAt(
    `/metrics${tab ? `?tab=${tab}` : ''}`,
    <Routes>
      <Route path="/metrics" element={<MetricsPage />} />
    </Routes>,
  );
}

function card(name: string): HTMLElement {
  return screen.getByRole('region', { name });
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the operational metrics', () => {
  it('counts the technical failures against the finished runs and the operator runs as the rest (DEC-64)', () => {
    expect(failedShare({ ...STATS.runs, completed: 6879, failed: 87 })).toBeCloseTo(87 / 6966);
    expect(failedShare({ ...STATS.runs, completed: 0, failed: 0 })).toBeNull();
    expect(operatorRuns(STATS.runs)).toBe(6872 - 2046);
    expect(axisEnd(16321)).toBe(20);
    expect(axisEnd(900)).toBe(5);
  });

  it("sets the overview from the portal's figures: the four cards, the mix, the uncounted requests and the settings", async () => {
    open('');
    const decisions = await screen.findByRole('group', { name: '판정' });
    expect(decisions).toHaveTextContent('13,733건');
    expect(decisions).toHaveTextContent('실행 6,872회의 단계별 판정');
    expect(screen.getByRole('group', { name: '판정 시간 중앙값' })).toHaveTextContent('6.0초');
    expect(screen.getByRole('group', { name: '판정 시간 중앙값' })).toHaveTextContent('p95 16.3초');
    expect(screen.getByRole('group', { name: '완료 실행' })).toHaveTextContent(
      `기술적 실패로 중단 87회 · 끝난 실행의 ${((87 / (6872 + 87)) * 100).toFixed(1)}%`,
    );
    expect(screen.getByRole('group', { name: '방문자 실행' })).toHaveTextContent('나머지 4,826회는 운영자 측정 · 점검');
    const mix = within(card('판정 분포')).getByRole('list', { name: '판정 분포' });
    expect(within(mix).getAllByRole('listitem').map((item) => item.textContent)).toEqual([
      '허용 9,932',
      '추가 인증 2,148',
      '검토 보류 1,136',
      '차단 517',
    ]);
    const uncounted = card('판정 수에 넣지 않은 요청');
    expect(uncounted).toHaveTextContent('6,844');
    expect(uncounted).toHaveTextContent('572');
    expect(uncounted).not.toHaveTextContent('613');
    const settings = card('운영 설정');
    expect(settings).toHaveTextContent('ENFORCE');
    expect(settings).toHaveTextContent('적용 모드');
    expect(settings).toHaveTextContent('204종');
    expect(settings).toHaveTextContent('3 / 3');
    expect(screen.getByText('기간 2026-10-04 ~ 2026-10-31 (세계 표준시)')).toBeInTheDocument();
    expect(screen.getByText('계산 시각 2026-10-31 16:49 세계 표준시 · 1분마다 다시 계산')).toBeInTheDocument();
  });

  it('puts the holds stopped before the response inside the holds, never among the uncounted requests (DEC-65)', async () => {
    open('decisions');
    const table = await screen.findByRole('table', { name: '판정별 수' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows.map((row) => row.textContent)).toEqual([
      '허용9,93272.3%',
      '추가 인증2,14815.6%',
      '검토 보류1,1368.3%',
      '차단5173.8%',
    ]);
    const after = card('검토 보류 · 차단 뒤의 처리');
    expect(after).toHaveTextContent('검토 보류 1,136건 가운데 613건');
    expect(after).toHaveTextContent('86건');
    expect(after).toHaveTextContent('0건');
    expect(within(card('판정 수에 넣지 않은 요청')).getAllByRole('term')).toHaveLength(2);
  });

  it('draws the latency on one axis from zero to the p95 rounded up, and the two ways a decision applies', async () => {
    open('latency');
    expect(
      await screen.findByRole('img', { name: '판정 시간 띠: p50 6.0초 · p95 16.3초, 축 0~20초' }),
    ).toBeInTheDocument();
    expect(card('적용 시점')).toHaveTextContent('동기 판정: 응답 전에 적용합니다.');
    expect(screen.getByRole('link', { name: 'AI 판정 엔진 › 판정 흐름' })).toHaveAttribute('href', '/engine?tab=flow');
  });

  it('lists the runs, today since midnight UTC and the runs by their ground truth, the effect left to the validation', async () => {
    open('runs');
    const runs = await screen.findByRole('region', { name: '실행' });
    expect(runs).toHaveTextContent('오늘 방문자 실행(세계 표준시 자정부터)8회');
    expect(runs).toHaveTextContent('2026-10-04 23:55 세계 표준시');
    const scope = card('정답이 있는 실행');
    expect(scope).toHaveTextContent('3,078회');
    expect(scope).toHaveTextContent('2,193회');
    expect(scope).toHaveTextContent('1,601회');
    expect(within(scope).getByRole('link', { name: '시나리오 검증' })).toHaveAttribute('href', '/validation');
  });

  it('lists every published recording with its agreement', async () => {
    open('agreement');
    const table = await screen.findByRole('table', { name: '반복 판정 일치' });
    expect(within(table).getAllByRole('row')).toHaveLength(STATS.agreement.recordings.length + 1);
    expect(within(table).getAllByRole('row')[1]).toHaveTextContent('A3위협2 / 2');
    expect(screen.getByText('전체 3 / 3 일치')).toBeInTheDocument();
  });

  it('says the states the answer can be in: an error, no decision, no latency, no run, no recording, an unknown tab (ST-73~ST-77, ST-82)', async () => {
    const failed = open('', 500);
    expect(await screen.findByText('불러오기 실패')).toBeInTheDocument();
    failed.unmount();
    vi.unstubAllGlobals();
    const empty: StatsView = {
      ...STATS,
      engineActions: { ALLOW: 0, CHALLENGE: 0, BLOCK: 0, ESCALATE: 0 },
      engineDecisions: 0,
      decisionTime: { decisions: 0, p50Ms: null, p95Ms: null },
      spec: null,
      agreement: { agreeing: 0, repetitions: 0, recordings: [] },
    };
    const none = open('nothing', empty);
    expect(await screen.findByText('아직 판정이 없습니다.')).toBeInTheDocument();
    expect(screen.getAllByText('판정 시간 기록 없음').length).toBeGreaterThan(0);
    expect(screen.getByText('완료 실행이 없습니다.')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: '개요' })).toHaveAttribute('aria-selected', 'true');
    none.unmount();
    vi.unstubAllGlobals();
    open('agreement', empty);
    expect(await screen.findByText('공개 녹화 기록이 없습니다.')).toBeInTheDocument();
  });

  it('opens every tab from the real answer', async () => {
    for (const tab of ['overview', 'decisions', 'latency', 'runs', 'agreement']) {
      const shown = open(tab);
      expect(await screen.findByRole('heading', { level: 1, name: '운영 지표' }), tab).toBeInTheDocument();
      expect(await screen.findByRole('tabpanel'), tab).toBeInTheDocument();
      shown.unmount();
      vi.unstubAllGlobals();
    }
  });
});
