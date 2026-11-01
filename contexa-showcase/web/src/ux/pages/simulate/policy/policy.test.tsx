import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LiveRunView } from '../../../../api/types';
import i18n from '../../../../i18n';
import menu from '../../../test/fixtures/agent-menu.test.json';
import menuAnswer from '../../../test/fixtures/agent-menu-answer.test.json';
import beforeS13 from '../../../test/fixtures/before-S13.test.json';
import labOptions from '../../../test/fixtures/lab-options.test.json';
import liveConfig from '../../../test/fixtures/live-config.test.json';
import rulesCases from '../../../test/fixtures/rules-cases.test.json';
import versusLab from '../../../test/fixtures/versus-lab.test.json';
import rulesDefault from '../../../test/fixtures/rules-default.test.json';
import volume0 from '../../../test/fixtures/rules-volume-0.test.json';
import volume50 from '../../../test/fixtures/rules-volume-50.test.json';
import volume100 from '../../../test/fixtures/rules-volume-100.test.json';
import volume200 from '../../../test/fixtures/rules-volume-200.test.json';
import volume300 from '../../../test/fixtures/rules-volume-300.test.json';
import volume400 from '../../../test/fixtures/rules-volume-400.test.json';
import volume1000 from '../../../test/fixtures/rules-volume-1000.test.json';
import { renderAt, stubPortal, type PortalStub } from '../../../test/portal';
import PolicyPage from './PolicyPage';

/** The rule engine's real answers by the export limit (POST /api/rules/evaluate, 2026-10-31). */
const BY_VOLUME: Readonly<Record<number, unknown>> = {
  0: volume0,
  50: volume50,
  100: volume100,
  200: volume200,
  300: volume300,
  400: volume400,
  500: rulesDefault,
  1000: volume1000,
};
const DEFAULT_LIMIT = rulesCases.defaults.settings.volumeLimit;

const BASE: Record<string, unknown> = {
  '/api/visitor': { predictions: {}, csrfHeader: 'X-XSRF-TOKEN' },
  '/api/journey': {
    state: { route: 'DEFAULT', act: 0, step: 'start', differences: [], predictions: {} },
    runs: [],
    predictions: [],
  },
  '/api/live/config': liveConfig,
  '/api/rules/cases': rulesCases,
  '/api/lab/options': labOptions,
  '/api/agent-menu': menu,
  [`/api/agent-menu/${menuAnswer.caseKey}/${menuAnswer.path}`]: menuAnswer,
};

/** The rule engine decides each setting; only the export limit varies in these tests. */
function rules(path: string, body: unknown) {
  if (path !== '/api/rules/evaluate') {
    return undefined;
  }
  const limit = (body as { volumeLimit: number }).volumeLimit;
  const answer = BY_VOLUME[limit];
  return answer ? { status: 200, body: answer } : { status: 500, body: {} };
}

function serve(
  extra: PortalStub['get'] = {},
  postAnswers: PortalStub['postAnswers'] = {},
  postReply: PortalStub['postReply'] = rules,
) {
  return stubPortal({ get: { ...BASE, ...extra }, postAnswers, postReply });
}

function open(address: string) {
  return renderAt(
    address,
    <Routes>
      <Route path="/simulate/policy" element={<PolicyPage />} />
    </Routes>,
  );
}

type Tally = { attacks: number; attacksStopped: number; normals: number; normalsBlocked: number; normalsChecked: number };
const tally = (answer: unknown, control: string) =>
  (answer as { tallies: Record<string, Tally> }).tallies[control] as Tally;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('thresholds', () => {
  it('decides the recorded runs again with the default and shows each control beside Contexa', async () => {
    serve();
    open('/simulate/policy');
    const table = await screen.findByRole('table', { name: '통제별 판정 결과' });
    const c1 = tally(rulesDefault, 'C1');
    const contexa = tally(rulesDefault, 'D');
    const rule = await within(table).findByRole('row', { name: /임계값 규칙/ });
    expect(rule).toHaveTextContent(`${c1.attacksStopped} / ${c1.attacks}`);
    expect(rule).toHaveTextContent(`${c1.normalsBlocked} / ${c1.normals}`);
    expect(rule).toHaveTextContent('기본값과 같음');
    const row = within(table).getByRole('row', { name: /Contexa/ });
    expect(row).toHaveTextContent(`${contexa.attacksStopped} / ${contexa.attacks}`);
    expect(row).toHaveTextContent(`정상 업무 ${contexa.normalsChecked}건은 차단 대신 추가 인증`);
    expect(screen.getByText(/대상: 시나리오별 가장 최근 실제 실행 35건\(공격 19 · 정상 업무 16\)/)).toBeInTheDocument();
  });

  it('decides the same runs at each value of the limit and reads the change from the results', async () => {
    serve();
    open('/simulate/policy');
    const sweep = await screen.findByRole('table', { name: '값별 결과' });
    const detected = within(sweep).getByRole('row', { name: /탐지한 공격/ });
    await waitFor(() =>
      expect(within(detected).getAllByRole('cell').map((cell) => cell.textContent)).toEqual(
        [0, 50, 100, 200, 300, 400, 500, 1000].map((value) => String(tally(BY_VOLUME[value], 'C1').attacksStopped)),
      ),
    );
    const low = tally(volume0, 'C1');
    const base = tally(rulesDefault, 'C1');
    expect(
      screen.getByText(
        `값을 ${DEFAULT_LIMIT}에서 0(으)로 낮추면 탐지한 공격은 ${base.attacksStopped}건에서 ${low.attacksStopped}건으로, 차단된 정상 업무는 ${base.normalsBlocked}건에서 ${low.normalsBlocked}건으로 바뀝니다. 건수 기준만으로는 공격과 정상 업무를 가르기 어렵습니다.`,
      ),
    ).toBeInTheDocument();
  });

  it('asks the rule engine once the typed value settles and keeps it in the address', async () => {
    const posts = serve();
    open('/simulate/policy');
    const box = await screen.findByRole('textbox', { name: '1회 반출 건수 상한' });
    fireEvent.change(box, { target: { value: '300' } });
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('knob=volumeLimit&value=300'));
    const row = await screen.findByRole('row', { name: /임계값 규칙/ });
    await waitFor(() => expect(row).toHaveTextContent('바꾼 값으로 다시 판정'));
    expect(
      posts.some(
        (post) => post.path === '/api/rules/evaluate' && (post.body as { volumeLimit: number }).volumeLimit === 300,
      ),
    ).toBe(true);
  });

  it('says when the rule engine could not decide, instead of dropping the table (ST-34)', async () => {
    serve({}, {}, () => ({ status: 500, body: {} }));
    open('/simulate/policy?tab=threshold&knob=volumeLimit&value=300');
    expect(
      (await screen.findAllByText('규칙 엔진이 이 값을 판정하지 못했습니다. 값을 바꾸거나 잠시 뒤 다시 엽니다.')).length,
    ).toBeGreaterThan(0);
  });
});

describe('composing one change', () => {
  it('says when the scenarios could not be loaded, instead of loading for ever (ST-35)', async () => {
    serve({ '/api/lab/options': 500 });
    open('/simulate/policy?tab=compose');
    expect(await screen.findByText('시나리오 목록을 불러오지 못했습니다. 잠시 뒤 다시 엽니다.')).toBeInTheDocument();
  });

  it('compares what the engine receives as designed, and says when the changed one was never sent (ST-36)', async () => {
    serve({}, {}, (path, body) => {
      if (path !== '/api/lab/before') {
        return undefined;
      }
      return (body as { conditions: unknown }).conditions === null
        ? { status: 200, body: beforeS13 }
        : { status: 404, body: {} };
    });
    open('/simulate/policy?tab=compose&case=S13&field=place&to=EXTERNAL');
    const before = await screen.findByRole('table', { name: '전송 전 입력 비교' });
    const usual = await within(before).findByRole('row', { name: /기준선 이탈/ });
    expect(usual).toHaveTextContent(`${beforeS13.comparison.departureCount}개`);
    expect(within(before).queryByText('달라짐')).not.toBeInTheDocument();
    expect(
      screen.getByText('바꾼 조건으로 보낸 실제 요청이 아직 없어, 실행해야 엔진이 받는 것을 알 수 있습니다.'),
    ).toBeInTheDocument();
  });

  it('sends the change with the call and keeps the run in the address', async () => {
    const view: LiveRunView = {
      liveRunId: 'live-c1',
      scenario: 'S13',
      status: 'QUEUED',
      queuePosition: 1,
      queueWaitSeconds: null,
      runId: null,
      readyMs: null,
      steps: [],
      challenge: null,
      failure: null,
    };
    const posts = serve({}, { '/api/lab/runs': { status: 202, body: { run: view, designed: false, changed: ['place'] } } });
    open('/simulate/policy?tab=compose&case=S13&field=place&to=EXTERNAL');
    await userEvent.click(await screen.findByRole('radio', { name: '공격' }));
    const run = screen.getByRole('button', { name: '조건을 바꿔 실행' });
    await waitFor(() => expect(run).not.toHaveAttribute('aria-disabled'));
    await userEvent.click(run);
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('sent=live-c1'));
    expect(posts.find((post) => post.path === '/api/lab/runs')?.body).toEqual({
      caseKey: 'S13',
      conditions: { place: 'EXTERNAL' },
      prediction: { call: 'ATTACK', approaches: {} },
      turnstileToken: null,
    });
  });

  it('names a run still in progress and the composition the portal refused (ST-37)', async () => {
    serve({}, { '/api/lab/runs': { status: 409, body: { reason: 'RUN_IN_PROGRESS' } } });
    const first = open('/simulate/policy?tab=compose&case=S13&field=place&to=EXTERNAL');
    await userEvent.click(await screen.findByRole('radio', { name: '모르겠음' }));
    const run = screen.getByRole('button', { name: '조건을 바꿔 실행' });
    await waitFor(() => expect(run).not.toHaveAttribute('aria-disabled'));
    await userEvent.click(run);
    expect(await screen.findByText('진행 중인 실행이 있습니다. 그 실행이 끝난 뒤 다시 보냅니다.')).toBeInTheDocument();
    first.unmount();
    serve({}, { '/api/lab/runs': { status: 400, body: { reason: 'STEPS_FIXED' } } });
    open('/simulate/policy?tab=compose&case=S13&field=place&to=EXTERNAL');
    await userEvent.click(await screen.findByRole('radio', { name: '모르겠음' }));
    const again = screen.getByRole('button', { name: '조건을 바꿔 실행' });
    await waitFor(() => expect(again).not.toHaveAttribute('aria-disabled'));
    await userEvent.click(again);
    expect(await screen.findByText('포털이 이 구성을 받지 않았습니다(STEPS_FIXED).')).toBeInTheDocument();
  });
});

describe("the composed run's result", () => {
  it("compares with the latest run as designed, and shows each control's answer where no grade exists (ST-38)", async () => {
    const run = versusLab.now.runId;
    const against = versusLab.before.runId;
    serve({
      '/api/live/runs/current': {
        liveRunId: 'live-c1',
        scenario: 'S13T',
        status: 'COMPLETED',
        queuePosition: 0,
        queueWaitSeconds: null,
        runId: run,
        readyMs: null,
        steps: [],
        challenge: null,
        failure: null,
      },
      '/api/lab/runs/recent': [{ runId: run, caseKey: 'S13T', referenceRunId: against }],
      [`/api/runs/${run}/versus?against=${against}`]: versusLab,
    });
    open('/simulate/policy?tab=compose&case=S13T&field=items&to=40&sent=live-c1');
    const result = await screen.findByRole('region', { name: /실행 결과/ });
    const waf = await within(result).findByRole('row', { name: /웹 방화벽/ });
    expect(within(waf).getByText('정상 처리')).toBeInTheDocument();
    expect(within(waf).getByText('허용')).toBeInTheDocument();
    expect(within(result).getByText(`반출 ${versusLab.before.exposedItems}건 → ${versusLab.now.exposedItems}건`, { exact: false })).toBeInTheDocument();
  });
});

describe('agent policy', () => {
  it('reads the stored answers only, says when one is not stored yet, and leads to the real run (ST-39)', async () => {
    serve();
    open('/simulate/policy?tab=agent');
    const edit = await screen.findByRole('region', { name: '위임 값을 하나 바꾸면' });
    expect(await within(edit).findByText('아직 저장된 답이 없습니다.')).toBeInTheDocument();
    expect(within(edit).getByRole('link', { name: /이 값으로 실제 실행/ })).toHaveAttribute(
      'href',
      `/simulate/agent/${liveConfig.delegationEdit.case}/review?quantity=40&period=VALID&operations=READ_EXPORT`,
    );
    const stored = screen.getByRole('region', { name: '시나리오 · 요청 경로별 저장된 답' });
    expect(await within(stored).findByText(menuAnswer.run.runId)).toBeInTheDocument();
    expect(within(stored).getByRole('table', { name: '에이전트가 보낸 요청' })).toBeInTheDocument();
  });
});
