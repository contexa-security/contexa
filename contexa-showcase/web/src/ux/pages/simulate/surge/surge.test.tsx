import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LiveRunView } from '../../../../api/types';
import i18n from '../../../../i18n';
import caseM41A from '../../../test/fixtures/agent-case-M41A.test.json';
import ownBurst from '../../../test/fixtures/agent-run-burst.test.json';
import runN1 from '../../../test/fixtures/agent-run-n1.test.json';
import anatomiesA6 from '../../../test/fixtures/anatomies-A6.test.json';
import anatomiesA6T from '../../../test/fixtures/anatomies-A6T.test.json';
import labOptions from '../../../test/fixtures/lab-options.test.json';
import liveConfig from '../../../test/fixtures/live-config.test.json';
import measuredA6 from '../../../test/fixtures/measured-A6.test.json';
import measuredA6T from '../../../test/fixtures/measured-A6T.test.json';
import resultsA6 from '../../../test/fixtures/results-A6.test.json';
import resultsA6T from '../../../test/fixtures/results-A6T.test.json';
import m41aOff from '../../../test/fixtures/snapshot-m41a-off.test.json';
import m41aOn from '../../../test/fixtures/snapshot-m41a-on.test.json';
import m41tOff from '../../../test/fixtures/snapshot-m41t-off.test.json';
import m41tOn from '../../../test/fixtures/snapshot-m41t-on.test.json';
import m41xOff from '../../../test/fixtures/snapshot-m41x-off.test.json';
import m41xOn from '../../../test/fixtures/snapshot-m41x-on.test.json';
import { renderAt, stubPortal, type PortalStub } from '../../../test/portal';
import SurgePage from './SurgePage';

const JOURNEY = {
  state: { route: 'DEFAULT', act: 0, step: 'start', differences: [], predictions: {} },
  runs: [],
  predictions: [],
};

/** The stored runs of the repeated read, step by step, as the portal answers them. */
function stepsOf(
  anatomies: { readonly runId: string; readonly steps: readonly unknown[] },
  results: { readonly runId: string; readonly steps: readonly unknown[] },
): Record<string, unknown> {
  return Object.fromEntries(
    anatomies.steps.flatMap((anatomy, index) => [
      [`/api/runs/${anatomies.runId}/steps/${index + 1}/anatomy`, anatomy],
      [`/api/runs/${results.runId}/steps/${index + 1}/result`, results.steps[index]],
    ]),
  );
}

const BASE: Record<string, unknown> = {
  '/api/visitor': { predictions: {}, csrfHeader: 'X-XSRF-TOKEN' },
  '/api/journey': JOURNEY,
  '/api/live/config': liveConfig,
  '/api/lab/options': labOptions,
  '/api/agent-cases/M41A': caseM41A,
  '/api/agent-snapshots/M41A-flights-on': m41aOn,
  '/api/agent-snapshots/M41A-flights-off': m41aOff,
  '/api/agent-snapshots/M41T-flights-on': m41tOn,
  '/api/agent-snapshots/M41T-flights-off': m41tOff,
  '/api/agent-snapshots/M41X-flights-on': m41xOn,
  '/api/agent-snapshots/M41X-flights-off': m41xOff,
  '/api/cases/A6/measured': measuredA6,
  '/api/cases/A6T/measured': measuredA6T,
  ...stepsOf(anatomiesA6, resultsA6),
  ...stepsOf(anatomiesA6T, resultsA6T),
};

function serve(extra: PortalStub['get'] = {}, postAnswers: PortalStub['postAnswers'] = {}) {
  return stubPortal({ get: { ...BASE, ...extra }, postAnswers });
}

function open(address: string) {
  return renderAt(
    address,
    <Routes>
      <Route path="/simulate/surge" element={<SurgePage />} />
    </Routes>,
  );
}

function liveView(over: Partial<LiveRunView>): LiveRunView {
  return {
    liveRunId: 'live-b1',
    scenario: 'M41A',
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

const D = (outcome: string) =>
  ({ D: { outcome, httpStatus: outcome === 'DELIVERED' ? 200 : 403, deliveredItems: 1, elapsedMs: 20 } }) as unknown as LiveRunView['steps'][number]['layers'];

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('requests sent at once', () => {
  it('composes the burst from the portal\'s settings and sends the chosen number after a confirmation (ST-32)', async () => {
    const posts = serve({}, { '/api/live/runs': { status: 202, body: liveView({}) } });
    open('/simulate/surge');
    expect(await screen.findByText(liveConfig.burst.title.ko)).toBeInTheDocument();
    const choices = screen.getByRole('radiogroup', { name: '동시에 보낼 요청 수' });
    expect(within(choices).getAllByRole('radio').map((radio) => radio.textContent)).toEqual(['1건', '3건', '5건', '10건']);
    expect(within(choices).getByRole('radio', { name: '10건' })).toHaveAttribute('aria-checked', 'true');
    await userEvent.click(within(choices).getByRole('radio', { name: '3건' }));
    const send = screen.getByRole('button', { name: '3건 동시 전송' });
    await waitFor(() => expect(send).not.toHaveAttribute('aria-disabled'));
    await userEvent.click(send);
    const dialog = await screen.findByRole('dialog', { name: '같은 요청 3건을 동시에 보냅니다' });
    expect(within(dialog).getByText(/에이전트 실행 1회와 실행 점수 5점을 씁니다/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: '3건 동시 전송' }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]).toEqual({ path: '/api/live/runs', body: { scenario: 'M41A', turnstileToken: null, copies: 3 } });
  });

  it('locks the send without the day\'s agent runs or enough run points, saying why (ST-32)', async () => {
    serve({ '/api/live/config': { ...liveConfig, remainingAgentToday: 0 } });
    const first = open('/simulate/surge');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '10건 동시 전송' })).toHaveAccessibleDescription(
        '오늘 에이전트 실행을 모두 썼습니다',
      ),
    );
    first.unmount();
    serve({ '/api/live/config': { ...liveConfig, remainingToday: 2 } });
    open('/simulate/surge');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '10건 동시 전송' })).toHaveAccessibleDescription(
        '오늘 남은 실행 점수가 5점보다 적습니다',
      ),
    );
  });

  it('compares the stored measurement of merging on and off, in the server\'s own counts', async () => {
    serve();
    open('/simulate/surge');
    const on = m41aOn.summary;
    const off = m41aOff.summary;
    const table = await screen.findByRole('table', { name: '판정 통합 결과' });
    const calls = within(table).getByRole('row', { name: /모델 호출/ });
    expect(within(calls).getAllByRole('cell').map((cell) => cell.textContent)).toEqual([
      String(on.modelCalls),
      String(off.modelCalls),
    ]);
    expect(
      screen.getByText(
        `판정 통합을 켜면 같은 요청 ${on.requests}건에 모델 호출이 ${off.modelCalls}회에서 ${on.modelCalls}회로 줄고, 전달은 ${on.delivered}건으로 같습니다`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText('다른 급증 측정 2건', { selector: 'summary' })).toBeInTheDocument();
  });

  it('counts the requests as they arrive and fills the model calls once stored (ST-33, DEC-31)', async () => {
    serve({
      '/api/live/runs/current': liveView({
        steps: [
          { stepNo: 1, operation: 'DOCUMENT_LIST', layers: D('DELIVERED') },
          { stepNo: 2, operation: 'DOCUMENT_LIST', layers: D('DELIVERED') },
          { stepNo: 3, operation: 'DOCUMENT_LIST', layers: D('REFUSED') },
        ],
      }),
    });
    open('/simulate/surge');
    const counters = await screen.findByRole('region', { name: /동시 전송/ });
    expect(within(counters).getByText('보낸 요청').nextSibling).toHaveTextContent('3');
    expect(within(counters).getByText('전달').nextSibling).toHaveTextContent('2');
    expect(within(counters).getByText('거부').nextSibling).toHaveTextContent('1');
    expect(within(counters).getByText('기록 저장 뒤 표시')).toBeInTheDocument();
  });

  it("reads the visitor's own burst from its record and says whether its decisions were merged (ST-33, DEC-31)", async () => {
    serve({
      '/api/journey': {
        state: { route: 'DEFAULT', act: 0, step: 'start', differences: [], predictions: {} },
        runs: [{ runId: ownBurst.runId, scenarioKey: 'M41A', classification: null, status: 'COMPLETED', lab: false }],
        predictions: [],
      },
      [`/api/runs/${ownBurst.runId}/agent`]: ownBurst,
    });
    open('/simulate/surge');
    const own = ownBurst.burst;
    expect(await screen.findByRole('columnheader', { name: `내 전송(${own.requests}건)` })).toBeInTheDocument();
    expect(
      screen.getByText(`내 전송: 요청 ${own.requests}건이 모두 각자 판정을 받았습니다. 이 실행에서는 판정 통합이 일어나지 않았습니다.`),
    ).toBeInTheDocument();
    const table = screen.getByRole('table', { name: '판정 통합 결과' });
    const calls = within(table).getByRole('row', { name: /모델 호출/ });
    expect(within(calls).getAllByRole('cell')[0]).toHaveTextContent(String(own.modelCalls));
  });

  it('names the sender and titles the measurement of sixty, with the first stop, its storing time and its requests (P-8, 옛 6-6)', async () => {
    // The stored runs come with their steps; the fixtures keep none, so the run's rows here are a real run's steps.
    const steps = runN1.steps.slice(0, 2);
    serve({ '/api/agent-snapshots/M41A-flights-on': { ...m41aOn, run: { ...m41aOn.run, steps } } });
    open('/simulate/surge');
    expect(await screen.findByText('요청 주체 · 위임 에이전트')).toBeInTheDocument();
    const measured = await screen.findByRole('region', { name: '동일 요청 60건 동시 유입(문서 목록)' });
    const table = within(measured).getByRole('table', { name: '판정 통합 결과' });
    const row = (name: string) =>
      within(within(table).getByRole('row', { name: new RegExp(`^${name}`) }))
        .getAllByRole('cell')
        .map((cell) => cell.textContent);
    expect(row('처음 멈춘 뒤 전달된 요청')).toEqual([
      String(m41aOn.summary.deliveredAfterFirstStop),
      String(m41aOff.summary.deliveredAfterFirstStop),
    ]);
    expect(row('처음 멈춘 요청')).toEqual(['멈추지 않음', '멈추지 않음']);
    expect(within(measured).getByText(/판정 통합 켬 측정 저장 시각 2026-10-26 15:29 \(세계 표준시\)/)).toBeInTheDocument();
    const timeline = within(measured).getByRole('table', { name: '판정 통합 켬 측정의 요청별 응답' });
    expect(within(timeline).getAllByRole('row')).toHaveLength(steps.length + 1);
    expect(within(timeline).getByRole('columnheader', { name: '자체 판정' })).toBeInTheDocument();
    expect(within(timeline).getAllByRole('columnheader', { name: '모델 호출' })).toHaveLength(1);
  });

  it('keeps every count of the other two measurements, merging off as well as on (P-8, 옛 6-6)', async () => {
    serve();
    open('/simulate/surge');
    const sensitive = await screen.findByRole('region', { name: '민감한 고객 기록 40건 동시 읽기', hidden: true });
    const table = within(sensitive).getByRole('table', { name: '민감한 고객 기록 40건 동시 읽기', hidden: true });
    const row = (name: string) =>
      within(within(table).getByRole('row', { name: new RegExp(`^${name}`), hidden: true }))
        .getAllByRole('cell', { hidden: true })
        .map((cell) => cell.textContent);
    expect(row('보낸 요청')).toEqual([String(m41tOn.summary.requests), String(m41tOff.summary.requests)]);
    expect(row('자체 판정이 있는 요청')).toEqual([
      String(m41tOn.summary.withVerdict),
      String(m41tOff.summary.withVerdict),
    ]);
    expect(row('처음 멈춘 요청')).toEqual([`요청 ${m41tOn.summary.firstStopStep}`, `요청 ${m41tOff.summary.firstStopStep}`]);
    expect(
      within(sensitive).getByText(/판정 통합 켬 측정 저장 시각 2026-10-26 15:29 \(세계 표준시\)/),
    ).toBeInTheDocument();
  });

  it('says a burst that did not finish and that the run is given back (ST-33)', async () => {
    serve({ '/api/live/runs/current': liveView({ status: 'FAILED' }) });
    open('/simulate/surge');
    expect(await screen.findByText('이번 실행은 끝까지 가지 못했습니다. 사용한 실행은 돌려받습니다.')).toBeInTheDocument();
  });
});

describe('the same lookup repeated', () => {
  it('sets the normal work beside the attack, each request with Contexa\'s decision or an earlier one', async () => {
    serve();
    open('/simulate/surge?tab=repeat');
    const attack = await screen.findByRole('region', { name: /^공격/ });
    await waitFor(() => expect(within(attack).getAllByText('앞선 판정으로 거절')).toHaveLength(4));
    expect(within(attack).getByText('다음 요청부터 적용')).toBeInTheDocument();
    const work = screen.getByRole('region', { name: /^정상 업무/ });
    await waitFor(() => expect(within(work).getAllByText('허용')).toHaveLength(5));
    expect(within(work).getByText('저장된 실제 실행')).toBeInTheDocument();
  });

  it('says the place in line of the normal work sent live, and a run that ended without its work (P-8, 옛 M-stack)', async () => {
    serve({
      '/api/live/runs/current': liveView({ scenario: 'A6T', status: 'QUEUED', queuePosition: 3, queueWaitSeconds: 40 }),
    });
    const first = open('/simulate/surge?tab=repeat');
    expect(await screen.findByText('대기 순서 3번 약 40초 남았습니다')).toBeInTheDocument();
    first.unmount();
    serve({ '/api/live/runs/current': liveView({ scenario: 'A6T', status: 'EXPIRED' }) });
    open('/simulate/surge?tab=repeat');
    expect(
      await screen.findByText('이번 실행은 판정을 끝내지 못했습니다. 다시 실행하면 새 판정을 받습니다.'),
    ).toBeInTheDocument();
  });
});
