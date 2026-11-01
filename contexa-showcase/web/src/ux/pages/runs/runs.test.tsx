import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import agentCaseN1 from '../../test/fixtures/agent-case-N1.test.json';
import agentCaseT5 from '../../test/fixtures/agent-case-T5.test.json';
import agentRunN1 from '../../test/fixtures/agent-run-n1.test.json';
import agentRunT5 from '../../test/fixtures/agent-run-t5-approve.test.json';
import anatomyAttacker from '../../test/fixtures/anatomy-attacker.test.json';
import anatomyInsider2 from '../../test/fixtures/anatomy-insider-2.test.json';
import anatomyN1 from '../../test/fixtures/anatomy-n1-last.test.json';
import anatomyOwner from '../../test/fixtures/anatomy-owner.test.json';
import benchmarkRuns from '../../test/fixtures/benchmark-runs.test.json';
import exchangesAttacker from '../../test/fixtures/exchanges-attacker.test.json';
import factsAttacker from '../../test/fixtures/facts-attacker.test.json';
import factsN1 from '../../test/fixtures/facts-n1-last.test.json';
import type { OtherBundleView, RunFacts } from '../../../api/promptQuality';
import hook from '../../test/fixtures/hook.test.json';
import liveConfig from '../../test/fixtures/live-config.test.json';
import measuredA3 from '../../test/fixtures/measured-A3.test.json';
import measuredA6T from '../../test/fixtures/measured-A6T.test.json';
import pairs from '../../test/fixtures/pairs.test.json';
import qualityAttacker from '../../test/fixtures/quality-attacker.test.json';
import receivedAttacker from '../../test/fixtures/received-attacker.test.json';
import replayA3 from '../../test/fixtures/replay-A3.test.json';
import resultAttacker from '../../test/fixtures/result-attacker.test.json';
import scoreAttacker from '../../test/fixtures/score-attacker.test.json';
import scoreInsider from '../../test/fixtures/score-insider.test.json';
import scoreOwner from '../../test/fixtures/score-owner.test.json';
import { formatDuration } from '../../format';
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

  it("sets an agent's delegated scope beside the request, each fact as the engine received it (DEC-81, 6-3)", async () => {
    serve({ [`${base(ATTACKER)}/steps/1/facts`]: factsN1 });
    open(`/runs/${ATTACKER}?tab=evidence`);
    expect(await screen.findByRole('heading', { level: 3, name: '위임 범위 대비 요청' })).toBeInTheDocument();
    const factsOf = (name: string) => screen.getByRole('heading', { level: 4, name }).parentElement as HTMLElement;
    const all = (factsN1 as unknown as RunFacts).blocks.flatMap((block) => block.facts);
    const delegation = all.find((fact) => fact.label === 'Delegation');
    expect(within(factsOf('위임 범위')).getByText(delegation?.factId ?? '')).toBeInTheDocument();
    expect(factsOf('위임 범위')).toHaveTextContent((delegation?.value ?? '').slice(0, 60));
    const request = factsOf('이 요청');
    expect(within(request).getAllByText(/^[RS]\d+$/).map((chip) => chip.textContent)).toEqual(
      ['Action', 'Target', 'TargetScope', 'Time', 'Credential', 'DelegationActivity'].map(
        (label) => all.find((fact) => fact.label === label)?.factId,
      ),
    );
  });

  it('has no delegated scope for a run without a delegation fact (a person)', async () => {
    serve();
    open(`/runs/${ATTACKER}?tab=evidence`);
    expect(await screen.findByRole('region', { name: '인용 사실과 판정 근거' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('region', { name: '가설 평가' })).toBeInTheDocument());
    expect(screen.queryByRole('heading', { name: '위임 범위 대비 요청' })).not.toBeInTheDocument();
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

/** The demo's step-up outcomes as the portal's teaser gives them (the old details' test values). */
const TEASERS = {
  computedAt: '2026-10-18T09:37:23Z',
  teasers: [
    {
      key: 'CHALLENGE_OUTCOMES',
      values: {
        outcomes: { ABANDONED: 84, ANSWERED: 214, EXPIRED: 127, NO_MAILBOX: 1847, 'code request 500': 2 },
        total: 2274,
        resumed: 200,
      },
      holds: null,
      source: { kind: 'CHALLENGES', ref: 'forced_action is null' },
      missing: null,
    },
  ],
};

/** Two minimum action rules of a v20 system text, as the core writes them (promptSections MINIMUM_ACTION_PLAIN). */
const P1 =
  'P1 MIN_P1_IDENTITY_DEVIATION: ResourceClass is SENSITIVE or CRITICAL and DeviationsFromBaseline names at least 2 of time, day, network and device as unexplained. Floor: CHALLENGE.';
const P3 =
  'P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no. Floor: ESCALATE (a verified user does not supply the missing record).';

/** One side of the other-bundle view, in the portal's shape (this test's own values). */
function bundleSide(runId: string, version: string) {
  return {
    runId,
    stepNo: 1,
    bundle: { version, hash: 'abcdef0123456789', selectionSource: 'REGISTRY' },
    userPrompt: '=== REQUEST ===',
    systemPromptLines: 106,
    userPromptLines: 52,
  };
}

const OTHER: OtherBundleView = {
  available: true,
  reason: null,
  current: bundleSide(ATTACKER, '2026.10.20-v21.8'),
  other: bundleSide('run-v19', '2026.10.11-v19.19'),
  lines: { before: 'v19', beforeLines: 252, after: 'v20', afterLines: 52 },
};

const N1 = agentRunN1.runId;
const T5_RUN = agentRunT5.runId;
const INSIDER = scoreInsider.runId;

describe('the facts the old decision details showed, kept in the new tabs (P-8, DEC-82)', () => {
  it('sums the decision process up, with the answer\'s source, its hash and the demo\'s step-ups', async () => {
    serve({ '/api/teasers': TEASERS });
    open(`/runs/${ATTACKER}`);
    const process = await screen.findByRole('region', { name: '판정 과정' });
    const timings = anatomyAttacker.interpretation.timings;
    const row = (name: string) => within(process).getByText(name).nextElementSibling as HTMLElement;
    expect(row('받은 업무 컨텍스트')).toHaveTextContent(`${anatomyAttacker.juxtaposition.companyFacts.length}줄`);
    expect(row('찾은 과거 기록')).toHaveTextContent(`${anatomyAttacker.context.rag.ragAuthorizedDocumentCount}건`);
    expect(row('프롬프트 만든 시간')).toHaveTextContent(`${formatDuration(timings.promptBuildMs, 'ko')}초`);
    expect(row('모델 응답 시간')).toHaveTextContent(`${formatDuration(timings.llmLatencyMs, 'ko')}초`);
    expect(row('2차 분석')).toHaveTextContent('1차 분석에서 판정');
    expect(row('후속 처리')).toHaveTextContent('추가 인증 · 코드가 계정 주인의 메일함으로 감');
    expect(await within(process).findByText('이 데모의 추가 인증 2,274건')).toBeInTheDocument();
    expect(within(process).getByText('통과 214건(그중 원래 요청을 다시 보냄 200건)')).toBeInTheDocument();
    expect(within(process).getByText('code request 500 2건')).toBeInTheDocument();
    const summary = screen.getByRole('region', { name: '판정 요약' });
    expect(within(summary).getByText('요청 때 저장한 시나리오 정의')).toBeInTheDocument();
    expect(within(summary).getByText(anatomyAttacker.truth.scenarioSha256)).toBeInTheDocument();
  });

  it('says a decision that applied while the response was being sent', async () => {
    const cut = {
      ...resultAttacker,
      layers: resultAttacker.layers.map((layer) =>
        layer.control === 'D' ? { ...layer, evidence: { ...layer.evidence, timing: 'MID_RESPONSE' } } : layer,
      ),
    };
    serve({ [`${base(ATTACKER)}/steps/1/result`]: cut });
    open(`/runs/${ATTACKER}`);
    const summary = await screen.findByRole('region', { name: '판정 요약' });
    expect(await within(summary).findByText(/응답을 보내는 도중 적용/)).toBeInTheDocument();
  });

  it('names the distinct facts cited, the export against the baseline\'s largest and the business context (2-4, 5-3)', async () => {
    serve();
    open(`/runs/${ATTACKER}?tab=evidence`);
    const cited = await screen.findByRole('region', { name: '인용 사실과 판정 근거' });
    const distinct = new Set(qualityAttacker.reasonCodes.map((code) => code.fact)).size;
    expect(await within(cited).findByText(new RegExp(`인용한 서로 다른 사실 ${distinct}개`))).toBeInTheDocument();
    const ratio = receivedAttacker.sizeRatio;
    expect(
      await within(cited).findByText(
        `반출 규모: 이번 ${ratio.items}건 · 기준선 최대 ${ratio.usualLargest}건 · 약 ${ratio.times}배`,
      ),
    ).toBeInTheDocument();
    const lines = anatomyAttacker.juxtaposition.companyFacts;
    expect(within(cited).getByText(`업무 컨텍스트 ${lines.length}줄 · 엔진이 불리하게 읽은 항목 0개`)).toBeInTheDocument();
    expect(within(cited).getByText('HX-310 담당')).toBeInTheDocument();
    expect(within(cited).getByText('승인 기록은 없지만 회사 규정상 이 요청에는 승인이 필요 없음')).toBeInTheDocument();
    expect(within(cited).getByText(lines[0] ?? '')).toBeInTheDocument();
    expect(within(cited).queryByText('불리 조건')).not.toBeInTheDocument();
  });

  it('marks a business record the engine read as adverse', async () => {
    const adverse = {
      ...receivedAttacker,
      companyAdverse: [{ label: 'approvalmissing', condition: 'ApprovalMissing', values: ['true'], met: true }],
      companyAdverseCount: 1,
    };
    serve({ [`${base(ATTACKER)}/steps/1/received`]: adverse });
    open(`/runs/${ATTACKER}?tab=evidence`);
    const record = await screen.findByText('승인 기록 없음');
    expect(within(record.parentElement as HTMLElement).getByText('불리 조건')).toBeInTheDocument();
    expect(screen.getByText(/엔진이 불리하게 읽은 항목 1개/)).toBeInTheDocument();
  });

  it("shows the prompt's inspection counts, each line's source and evidence grade, the minimum rules and the other bundle", async () => {
    const ruled = {
      ...receivedAttacker,
      minimumRules: {
        rules: [
          { code: 'MIN_P1_IDENTITY_DEVIATION', line: P1, floor: 'CHALLENGE', met: false },
          { code: 'MIN_P3_POLICY_NOT_SATISFIED', line: P3, floor: 'ESCALATE', met: true },
        ],
        applies: true,
      },
    };
    const adverse = {
      ...anatomyAttacker,
      juxtaposition: {
        ...anatomyAttacker.juxtaposition,
        coreAdverseLabels: [{ label: 'approvalmissing', condition: 'ApprovalMissing', values: ['true'], met: true }],
        adverseMet: 1,
        adverseChecked: 4,
      },
    };
    serve({
      [`${base(ATTACKER)}/steps/1/received`]: ruled,
      [`${base(ATTACKER)}/steps/1/anatomy`]: adverse,
      [`${base(ATTACKER)}/steps/1/other-bundle`]: OTHER,
    });
    open(`/runs/${ATTACKER}?tab=prompt`);
    const checks = await screen.findByRole('region', { name: '프롬프트 검사 수치' });
    const ribbon = qualityAttacker.ribbon;
    expect(within(checks).getByText(`${ribbon.withSource} / ${ribbon.facts}`)).toBeInTheDocument();
    expect(within(checks).getByText(`${ribbon.unknown}`)).toBeInTheDocument();
    expect(within(checks).getByText('통과에 불리한 조건').nextElementSibling).toHaveTextContent('1 / 4 · approvalmissing');
    const facts = screen.getByRole('region', { name: '판정 프롬프트의 사실' });
    await waitFor(() => expect(within(facts).getAllByText('학습').length).toBeGreaterThan(0));
    expect(within(facts).getAllByText('업무 시스템').length).toBeGreaterThan(0);
    expect(within(facts).getByText('근거 제한적 · 주의 표시 값 1개')).toBeInTheDocument();
    const rules = await screen.findByRole('region', { name: '최소 판정 규칙' });
    expect(within(rules).getAllByRole('row')).toHaveLength(3);
    expect(within(rules).getByText('충족')).toBeInTheDocument();
    expect(within(rules).getByText('해당 없음')).toBeInTheDocument();
    const other = await screen.findByRole('region', { name: '다른 번들로 보낸 같은 시나리오' });
    expect(within(other).getByText('상황 프롬프트 줄 수: v19 252줄 → v20 52줄')).toBeInTheDocument();
    expect(within(other).getByRole('link', { name: 'run-v19' })).toHaveAttribute('href', '/runs/run-v19?step=1');
  });

  it("lists the recorded values with their source, every call's figures and the prompts as sent (3-3, 5-3)", async () => {
    serve();
    open(`/runs/${ATTACKER}?tab=response`);
    const recorded = await screen.findByRole('region', { name: '기록된 판정 값' });
    const row = (name: string) => within(recorded).getByRole('rowheader', { name }).closest('tr') as HTMLElement;
    expect(row('위험도')).toHaveTextContent('0.35');
    expect(row('위험도')).toHaveTextContent('모델이 낸 값');
    expect(row('확신도')).toHaveTextContent('모델이 낸 값');
    expect(row('공격 기법(MITRE)')).toHaveTextContent('모델이 내지 않음');
    expect(row('인용 증거 종류')).toHaveTextContent('모델이 내지 않음');
    const calls = screen.getByRole('region', { name: '모델 호출 기록' });
    const call = anatomyAttacker.interpretation.calls[0];
    expect(within(calls).getByText((call?.promptTokens ?? 0).toLocaleString('ko-KR'))).toBeInTheDocument();
    expect(within(calls).getByText(String(call?.completionTokens))).toBeInTheDocument();
    expect(within(calls).getByText(`${formatDuration(call?.elapsedMs ?? 0, 'ko')}초`)).toBeInTheDocument();
    expect(within(calls).getByText('성공')).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: '모델 호출 1' })).toBeInTheDocument();
    const lines = anatomyAttacker.promptLines;
    expect(screen.getByText(`시스템 프롬프트(보낸 원문) · ${lines.systemPhysical}줄`)).toBeInTheDocument();
    expect(screen.getByText(`상황 프롬프트(보낸 원문) · ${lines.userPhysical}줄`)).toBeInTheDocument();
    const sent = exchangesAttacker.calls[0];
    expect(screen.getByLabelText('시스템 프롬프트(보낸 원문)')).toHaveTextContent(sent?.systemPrompt.slice(0, 40) ?? '');
    expect(screen.getByLabelText('상황 프롬프트(보낸 원문)')).toHaveTextContent(sent?.userPrompt.slice(0, 30) ?? '');
  });

  it('says a decision went on to the second pass, with that pass\'s own reason', async () => {
    serve({
      [`${base(INSIDER)}/score`]: scoreInsider,
      [`${base(INSIDER)}/steps/2/anatomy`]: anatomyInsider2,
    });
    open(`/runs/${INSIDER}?step=2`);
    const process = await screen.findByRole('region', { name: '판정 과정' });
    expect(within(process).getByText('2차 분석까지 진행')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: '모델 응답 원문' }));
    const heading = await screen.findByRole('heading', { level: 3, name: '2차 분석 사유(원문)' });
    const second = anatomyInsider2.interpretation.timings.events.find((event) => event.type === 'LAYER2_COMPLETE');
    expect(heading.nextElementSibling).toHaveTextContent(second?.reasoning ?? '');
    const calls = screen.getByRole('region', { name: '모델 호출 기록' });
    expect(within(calls).getAllByRole('row')).toHaveLength(anatomyInsider2.interpretation.calls.length + 1);
  });

  it("shows the bundle's hash and how it was selected, and every line the inspector found wrong", async () => {
    const wrong = {
      ...qualityAttacker,
      inspection: {
        ...qualityAttacker.inspection,
        verdict: 'FAIL',
        checks: qualityAttacker.inspection.checks.map((check) =>
          check.code === 'FACT_ACCURACY'
            ? {
                ...check,
                mismatched: 1,
                mismatches: [
                  {
                    block: 'DECISION_FACTS',
                    entry: 'Assignment',
                    factId: 'F4',
                    line: 31,
                    expected: 'HX-310',
                    actual: 'HX-311',
                    reason: 'VALUE_DIFFERS',
                  },
                ],
              }
            : check,
        ),
      },
    };
    serve({ [`${base(ATTACKER)}/steps/1/quality`]: wrong });
    open(`/runs/${ATTACKER}?tab=integrity`);
    const seal = await screen.findByRole('region', { name: '무결성 봉인' });
    expect(await within(seal).findByText(qualityAttacker.bundle.hash)).toBeInTheDocument();
    expect(within(seal).getByText(qualityAttacker.bundle.selectionSource)).toBeInTheDocument();
    const inspection = screen.getByRole('region', { name: '공식 검사' });
    const mismatches = within(inspection).getByRole('table', { name: '어긋난 줄' });
    expect(within(mismatches).getByText('F4')).toBeInTheDocument();
    expect(within(mismatches).getByText('HX-311')).toBeInTheDocument();
    expect(within(mismatches).getByText('VALUE_DIFFERS')).toBeInTheDocument();
  });

  it("names an agent run's sender and its case's operator recordings in the head (6-3)", async () => {
    serve({
      [`${base(N1)}/score`]: { ...scoreOwner, runId: N1, scenarioKey: 'N1', executedSteps: 6 },
      [`${base(N1)}/steps/6/anatomy`]: anatomyN1,
      [`${base(N1)}/agent`]: agentRunN1,
      '/api/agent-cases/N1': agentCaseN1,
    });
    open(`/runs/${N1}?step=6`);
    expect(await screen.findByText('AI 에이전트 요청 · 위임 에이전트')).toBeInTheDocument();
    const recorded = agentCaseN1.recorded;
    expect(
      await screen.findByText(`운영자 기록 ${recorded.runs}회 · 최근 기록과 같은 결과 ${recorded.sameAsLatest}회`),
    ).toBeInTheDocument();
  });

  it("sets an agent run beside its case's recorded normal pair: requests, deliveries and whether it finished (6-3)", async () => {
    serve({
      [`${base(T5_RUN)}/score`]: { ...scoreOwner, runId: T5_RUN, scenarioKey: 'T5' },
      [`${base(T5_RUN)}/steps/1/anatomy`]: anatomyOwner,
      [`${base(T5_RUN)}/agent`]: agentRunT5,
      '/api/agent-cases/T5': agentCaseT5,
      [`${base(N1)}/agent`]: agentRunN1,
    });
    open(`/runs/${T5_RUN}?tab=evidence`);
    expect(await screen.findByRole('heading', { level: 3, name: '같은 위임 범위의 정상 업무' })).toBeInTheDocument();
    expect(screen.getByText(`운영자가 기록한 정상 업무 시나리오 ${agentCaseT5.normalPair}의 실행`)).toBeInTheDocument();
    const link = screen.getByRole('link', { name: N1 });
    expect(link).toHaveAttribute('href', `/runs/${N1}`);
    const pair = link.closest('dl') as HTMLElement;
    expect(within(pair).getAllByText(`${agentRunN1.steps.length}건`)).toHaveLength(3);
    expect(within(pair).getByText('에이전트가 작업을 마치고 답함')).toBeInTheDocument();
  });
});

describe('the facts the old recorded replay showed, kept in the log (P-8, DEC-82)', () => {
  it("names a recorded scene's situation and its scenario's current measurement with this run in it", async () => {
    const sentence = pairs.find((pair) => pair.key === 'A3')?.question ?? { ko: '', en: '' };
    serve({
      '/api/replays/A3': { ...replayA3, scenes: replayA3.scenes.map((scene) => ({ ...scene, kind: 'ATTACK', sentence })) },
      '/api/cases/A3/measured': measuredA3,
    });
    const chosen = measuredA3.list[0];
    open(`/runs?run=${chosen?.runId ?? ''}`);
    const panel = await screen.findByRole('complementary');
    expect(await within(panel).findByText(sentence.ko)).toBeInTheDocument();
    const value = (name: string) => within(panel).getByText(name).nextElementSibling as HTMLElement;
    expect(await within(panel).findByText('측정 횟수')).toBeInTheDocument();
    expect(value('측정 횟수')).toHaveTextContent(`${measuredA3.runs}회`);
    expect(value('결과별 횟수')).toHaveTextContent(`처음부터 차단 ${measuredA3.results.STOPPED}회`);
    expect(value('이 실행')).toHaveTextContent(`포함 · 시작 ${chosen?.startedAt.slice(0, 16).replace('T', ' ')}`);
  });

  it('grades every control of the chosen run, an existing control that halted normal work as a false positive', async () => {
    const normal = benchmarkRuns.runs.find((run) => run.truth.classification === 'NORMAL' && run.business.C1.result === 'HALTED');
    serve({
      [`/api/cases/${normal?.scenarioKey ?? ''}/measured`]: {
        ...measuredA6T,
        caseKey: normal?.scenarioKey,
        runs: 3,
        results: { PASSED: 2, PASSED_AFTER_CHECK: 1 },
        list: [],
      },
    });
    open(`/runs?run=${normal?.runId ?? ''}`);
    const panel = await screen.findByRole('complementary');
    const control = (name: string) => within(panel).getByText(name).closest('li') as HTMLElement;
    await waitFor(() => expect(within(control('임계값 규칙')).getByText('오탐')).toBeInTheDocument());
    expect(within(control('웹 방화벽')).getByText('정상 처리')).toBeInTheDocument();
    const value = (name: string) => within(panel).getByText(name).nextElementSibling as HTMLElement;
    expect(await within(panel).findByText('결과별 횟수')).toBeInTheDocument();
    expect(value('결과별 횟수')).toHaveTextContent('추가 인증 뒤 처리 1회 · 정상 처리 2회');
    expect(value('이 실행')).toHaveTextContent('포함되지 않음');
  });
});
