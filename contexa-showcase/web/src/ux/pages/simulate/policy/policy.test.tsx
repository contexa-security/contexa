import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { BeforeSendView } from '../../../../api/anatomy';
import type { PeerAssessments, RecentLabRun } from '../../../../api/lab';
import type { LabDelta } from '../../../../api/promptQuality';
import type { AnalysisView, LiveRunView } from '../../../../api/types';
import i18n from '../../../../i18n';
import menu from '../../../test/fixtures/agent-menu.test.json';
import menuAnswer from '../../../test/fixtures/agent-menu-answer.test.json';
import burstRun from '../../../test/fixtures/agent-run-burst.test.json';
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

  it('says when no scenario moved, and names each moved one with its default and new handling (UC-5 L-rules)', async () => {
    serve();
    const first = open('/simulate/policy');
    await screen.findByRole('table', { name: '통제별 판정 결과' });
    expect(await screen.findByText('기본값과 결과가 달라진 시나리오가 없습니다.')).toBeInTheDocument();
    first.unmount();
    serve();
    open('/simulate/policy?tab=threshold&knob=volumeLimit&value=300');
    const moved = (volume300 as { changed: { scenario: string; before: boolean; now: boolean }[] }).changed;
    const list = await screen.findByRole('region', { name: `기본값과 결과가 달라진 상황 ${moved.length}개` });
    const s13 = within(list).getByText('S13').closest('li') as HTMLElement;
    expect(s13).toHaveTextContent('기본값 허용 → 바꾼 값 차단');
    expect(screen.queryByText('기본값과 결과가 달라진 시나리오가 없습니다.')).not.toBeInTheDocument();
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

  it('keeps a scenario without a ground truth apart from normal work (UC-5 5절)', async () => {
    // S07's definition sets UNCERTAIN (showcase-portal scenarios/S07.json); the shape is the lab options' own.
    const s07 = {
      ...labOptions.cases[2],
      key: 'S07',
      title: { ko: '정당성 근거가 부족한 예외', en: 'An exception without valid grounds' },
      classification: 'UNCERTAIN',
    };
    serve({ '/api/lab/options': { ...labOptions, cases: [...labOptions.cases, s07] } });
    open('/simulate/policy?tab=compose&case=S07');
    const select = await screen.findByRole('combobox', { name: '시나리오' });
    const group = (label: string) => select.querySelector(`optgroup[label="${label}"]`);
    expect(group('정답을 정하지 않은 시나리오')).toHaveTextContent('S07 · 정당성 근거가 부족한 예외');
    expect(group('정답이 정상 업무인 시나리오')).not.toHaveTextContent('S07');
    expect(group('정답이 정상 업무인 시나리오')).toHaveTextContent('S13T');
    expect(screen.getByText('정하지 않음(UNCERTAIN)')).toBeInTheDocument();
  });

  it("names the scenario's employee, its requests and every condition as designed (UC-5 L-case, L-change)", async () => {
    serve();
    const first = open('/simulate/policy?tab=compose&case=S16');
    const employee = labOptions.employees[0] as { displayName: string };
    expect(await screen.findByText(`${employee.displayName} · 설계 엔지니어`)).toBeInTheDocument();
    expect(
      screen.getByText('요청 3개가 이어지는 시나리오라 요청마다 정해진 동작 · 대상 · 건수는 바꿀 수 없습니다.'),
    ).toBeInTheDocument();
    const original = screen.getByText('원래 조건').closest('details') as HTMLElement;
    expect(within(original).getByText('요청 수').closest('div')).toHaveTextContent('3개');
    expect(within(original).getByText('장소').closest('div')).toHaveTextContent('사무실');
    first.unmount();
    serve();
    open('/simulate/policy?tab=compose&case=S13');
    const designed = (await screen.findByText('원래 조건')).closest('details') as HTMLElement;
    expect(within(designed).getByText('건수').closest('div')).toHaveTextContent('480건');
  });

  it("names the company records a case defines, S14's trip city among them (UC-5 4-4)", async () => {
    // S14's definition (showcase-portal scenarios/S14.json) puts one TRAVEL record in the business database; the
    // lab options carry every field of a record, the ones it does not state as null (as S16's DOCUMENT record here).
    const shape = labOptions.cases[2] as (typeof labOptions.cases)[number];
    const empty = Object.fromEntries(Object.keys(shape.facts[0] ?? {}).map((key) => [key, null]));
    const s14 = {
      ...shape,
      key: 'S14',
      title: { ko: '출장지에서 새 노트북으로 하는 새벽 정상 업무', en: 'Normal work at dawn from a business trip on a new laptop' },
      classification: 'NORMAL',
      facts: [{ ...empty, kind: 'TRAVEL', city: 'Singapore', country: 'SG', network: '198.51.100.0/24' }],
    };
    serve({ '/api/lab/options': { ...labOptions, cases: [...labOptions.cases, s14] } });
    open('/simulate/policy?tab=compose&case=S14');
    const trip = (await screen.findByText('출장')).closest('div');
    expect(trip).toHaveTextContent('싱가포르 · SG · 198.51.100.0/24');
  });

  it('names the minimum response rules the engine found met (UC-5 L-before)', async () => {
    const met: BeforeSendView = {
      ...(beforeS13.comparison as unknown as BeforeSendView),
      modelJudges: false,
      minimumRules: {
        rules: [
          { code: 'MIN_P1_IDENTITY_DEVIATION', line: 'P1 MIN_P1_IDENTITY_DEVIATION: x', floor: 'CHALLENGE', met: false },
          {
            code: 'MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT',
            line: 'P2 MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT: x',
            floor: 'CHALLENGE',
            met: true,
          },
        ],
        applies: true,
      },
    };
    serve({}, {}, (path) => (path === '/api/lab/before' ? { status: 200, body: { comparison: met } } : undefined));
    open('/simulate/policy?tab=compose&case=S13');
    const before = await screen.findByRole('table', { name: '전송 전 입력 비교' });
    const line = await within(before).findByRole('row', { name: /최소 대응 규칙/ });
    expect(line).toHaveTextContent('해당 · 민감한 자료를 새 단말 · 다른 네트워크로 반출 → 추가 인증 이상');
    expect(line).not.toHaveTextContent('기준선 이탈 둘 이상');
  });

  it("shows a queued run's place and wait (UC-5 L-send)", async () => {
    const queued: LiveRunView = {
      liveRunId: 'live-q1',
      scenario: 'S13',
      status: 'QUEUED',
      queuePosition: 2,
      queueWaitSeconds: 30,
      runId: null,
      readyMs: null,
      steps: [],
      challenge: null,
      failure: null,
    };
    serve({ '/api/live/runs/current': queued });
    open('/simulate/policy?tab=compose&case=S13&sent=live-q1');
    expect(await screen.findByText('대기 순서 2번 약 30초 남았습니다')).toBeInTheDocument();
  });

  it("shows each control's time and items, a stream's progress and Contexa's expected wait (UC-5 L-send)", async () => {
    const running: LiveRunView = {
      liveRunId: 'live-r1',
      scenario: 'S13',
      status: 'RUNNING',
      queuePosition: 0,
      queueWaitSeconds: null,
      runId: null,
      readyMs: 900,
      steps: [
        {
          stepNo: 1,
          operation: 'EXPORT',
          layers: { A: { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 480, elapsedMs: 27 } },
          streams: { D: { total: 480, delivered: 120, atMs: 2400 } },
        },
      ],
      challenge: null,
      failure: null,
    };
    const analysis: AnalysisView = {
      stepNo: 1,
      stages: [],
      decision: null,
      decisionWait: { medianMs: 9000, decisions: 12, settingHash: 'setting', waitedMs: 2000, remainingSeconds: 7 },
    };
    serve({ '/api/live/runs/current': running, '/api/live/runs/current/analysis?step=1': analysis });
    open('/simulate/policy?tab=compose&case=S13&sent=live-r1');
    const table = await screen.findByRole('table', { name: '실행 진행' });
    const row = within(table).getByRole('row', { name: /요청 1/ });
    expect(row).toHaveTextContent('0.027초 · 480건');
    expect(row).toHaveTextContent('2.4초 · 120 / 480건');
    expect(await screen.findByText('Contexa 판정 대기 · 약 7초 남음')).toBeInTheDocument();
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
    // versus-lab.test.json: the reference run is not a lab run, so the server names no changed condition.
    expect(within(result).getByText('서버가 찾은 두 실행의 다른 조건: —')).toBeInTheDocument();
  });

  it('shows the stored call and whether it was right, the changed conditions, the delivery check and the peers (UC-5 L-result)', async () => {
    const run = versusLab.now.runId;
    const against = versusLab.before.runId;
    const mine: RecentLabRun = {
      runId: run,
      caseKey: 'S13T',
      designed: true,
      changed: [],
      conditions: {},
      composedAt: '2026-10-31T10:00:00Z',
      call: 'ATTACK',
      approaches: {},
      referenceRunId: against,
      callRight: false,
    };
    const delta: LabDelta = {
      runId: run,
      baseRunId: against,
      condition: 'items',
      value: '40',
      available: true,
      reason: null,
      steps: [
        { stepNo: 1, changed: [], expected: ['dim.size'], unexpected: [], valueMatches: true, passed: true, notCompared: null },
      ],
    };
    const peers: PeerAssessments = {
      assessments: 3,
      assessors: 2,
      verdicts: { SOUND: 2, UNSURE: 1 },
      reasons: { OVERBLOCK: 1 },
      delayHours: 24,
    };
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
        challenge: {
          stage: 'NO_MAILBOX',
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
          reissueOutcome: null,
        },
        failure: null,
      },
      '/api/lab/runs/recent': [mine],
      [`/api/runs/${run}/versus?against=${against}`]: { ...versusLab, changedConditions: ['items'] },
      [`/api/lab/runs/${run}/delta`]: delta,
      [`/api/runs/${run}/steps/1/peer-assessments`]: peers,
    });
    open('/simulate/policy?tab=compose&case=S13T&sent=live-c1');
    expect(
      await screen.findByText('추가 인증 코드는 계정 주인의 메일함으로 가서, 탈취된 계정으로는 받을 수 없습니다.'),
    ).toBeInTheDocument();
    const result = await screen.findByRole('region', { name: /실행 결과/ });
    expect(await within(result).findByText(/^예상 판정 공격/)).toHaveTextContent('예상 판정 공격 정답과 다름');
    expect(within(result).getByText('서버가 찾은 두 실행의 다른 조건: 건수')).toBeInTheDocument();
    expect(
      await within(result).findByText('바꾼 조건은 판정 프롬프트의 해당 줄에만 들어갔습니다.', { exact: false }),
    ).toHaveTextContent(`비교 기준 실행 ${against}`);
    expect(
      await within(result).findByText('다른 방문자의 판정 평가 3건(방문자 2명) · 타당함 2 · 타당하지 않음 0 · 모르겠음 1'),
    ).toBeInTheDocument();
    expect(within(result).getByText('이유별 과잉 차단 1')).toBeInTheDocument();
    expect(within(result).getByText(/24시간이 지난 뒤부터 세고/)).toBeInTheDocument();
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

  it("names the senders, the portal's scoring per control and what a real agent run costs (UC-5 L-agent)", async () => {
    serve();
    open('/simulate/policy?tab=agent');
    const edit = await screen.findByRole('region', { name: '위임 값을 하나 바꾸면' });
    expect(
      await within(edit).findByText(
        `에이전트 실행은 1회에 하루 실행 한도 ${liveConfig.agentRunPoints}회분을 씁니다. · 오늘 모든 방문자에게 남은 실제 에이전트 실행 1,567회`,
      ),
    ).toBeInTheDocument();
    const stored = screen.getByRole('region', { name: '시나리오 · 요청 경로별 저장된 답' });
    await within(stored).findByText(menuAnswer.run.runId);
    const fact = (label: string) => within(stored).getByText(label).closest('div');
    expect(fact('시나리오 정의의 요청 주체')).toHaveTextContent('사람을 대신한 AI 에이전트(토큰 교환)');
    expect(fact('이 실행의 요청 주체')).toHaveTextContent('AI 에이전트 자신의 자격');
    expect(fact('보낸 요청(포털 집계)')).toHaveTextContent(String(menuAnswer.run.proof.sent));
    expect(fact('업무에 필요한 양')).toHaveTextContent(String(menuAnswer.run.proof.workNeeds));
    const proof = within(stored).getByRole('table', { name: '통제별 반출 · 필요 이상(포털 집계)', hidden: true });
    const contexa = menuAnswer.run.proof.controls.D;
    const row = within(proof).getByRole('row', { name: /Contexa/, hidden: true });
    expect(within(row).getAllByRole('cell', { hidden: true }).map((cell) => cell.textContent)).toEqual([
      `요청 ${contexa.firstStopStep}`,
      String(contexa.documents),
      String(contexa.items),
      String(contexa.records),
      String(contexa.changes),
      String(contexa.beyondNeed),
    ]);
    expect(within(proof).getByRole('row', { name: /웹 방화벽/, hidden: true })).toHaveTextContent('멈추지 않음');
  });

  it('counts each burst of alike requests as the old timeline folded it (UC-5 L-agent)', async () => {
    // Six copies of the burst run's first stored request (agent-run-burst.test.json), one after another.
    const step = burstRun.steps[0] as (typeof burstRun.steps)[number];
    const steps = Array.from({ length: 6 }, (_, index) => ({ ...step, stepNo: index + 1 }));
    serve({
      [`/api/agent-menu/${menuAnswer.caseKey}/${menuAnswer.path}`]: { ...menuAnswer, run: { ...menuAnswer.run, steps } },
    });
    open('/simulate/policy?tab=agent');
    const stored = await screen.findByRole('region', { name: '시나리오 · 요청 경로별 저장된 답' });
    expect(
      await within(stored).findByText('같은 요청 6건(요청 1~6) · 자체 판정 6건 · 모델 호출 6번'),
    ).toBeInTheDocument();
  });
});
