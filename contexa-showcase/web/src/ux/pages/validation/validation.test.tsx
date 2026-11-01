import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import agent from '../../test/fixtures/benchmark-agent.test.json';
import full from '../../test/fixtures/benchmark-full.test.json';
import cases from '../../test/fixtures/cases.test.json';
import decision from '../../test/fixtures/decision-quality.test.json';
import prompt from '../../test/fixtures/prompt-quality.test.json';
import settings from '../../test/fixtures/settings.test.json';
import m41aOff from '../../test/fixtures/snapshot-m41a-off.test.json';
import m41aOn from '../../test/fixtures/snapshot-m41a-on.test.json';
import m41tOff from '../../test/fixtures/snapshot-m41t-off.test.json';
import m41tOn from '../../test/fixtures/snapshot-m41t-on.test.json';
import m41xOff from '../../test/fixtures/snapshot-m41x-off.test.json';
import m41xOn from '../../test/fixtures/snapshot-m41x-on.test.json';
import { renderAt, stubPortal, type PortalStub } from '../../test/portal';
import ValidationPage from './ValidationPage';

/** The portal's real answers (src/ux/test/fixtures, captured by ux_fixtures_i6.py on 2026-10-31). */
const SETTING = full.spec.settingHash;
const BASE: Record<string, unknown> = {
  '/api/visitor': { predictions: {}, csrfHeader: 'X-XSRF-TOKEN' },
  '/api/benchmark': full,
  [`/api/benchmark/decision-quality?setting=${SETTING}`]: decision,
  [`/api/benchmark/prompt-quality?setting=${SETTING}`]: 404,
  '/api/benchmark/prompt-quality': prompt,
  '/api/benchmark/agent': agent,
  '/api/cases': cases,
  '/api/settings': settings,
  '/api/agent-snapshots/M41A-flights-off': m41aOff,
  '/api/agent-snapshots/M41A-flights-on': m41aOn,
  '/api/agent-snapshots/M41T-flights-off': m41tOff,
  '/api/agent-snapshots/M41T-flights-on': m41tOn,
  '/api/agent-snapshots/M41X-flights-off': m41xOff,
  '/api/agent-snapshots/M41X-flights-on': m41xOn,
};

function serve(extra: PortalStub['get'] = {}) {
  return stubPortal({ get: { ...BASE, ...extra } });
}

function open(address: string) {
  return renderAt(
    address,
    <Routes>
      <Route path="/validation" element={<ValidationPage />} />
    </Routes>,
  );
}

const control = (key: string) => {
  const found = full.controls.find((score) => score.control === key);
  if (!found) {
    throw new Error(`no control ${key}`);
  }
  return found;
};

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the scenario validation', () => {
  it("says first that it is our own measurement, and sums the runs up with the portal's counts (DEC-51)", async () => {
    serve();
    open('/validation');
    expect(await screen.findByText('자체 측정 — 외부 표준 결과가 아닙니다.')).toBeInTheDocument();
    const fewest = Math.min(
      ...full.controls.filter((score) => score.control !== 'D').map((score) => score.missed),
    );
    expect(
      screen.getByText(`Contexa 미탐 ${control('D').missed}회 · 기존 통제 최저 미탐 ${fewest}회`),
    ).toBeInTheDocument();
    const table = screen.getByRole('table', { name: '보안 통제별 미탐 · 오탐' });
    const names: Record<string, string> = {
      A: '웹 방화벽(WAF)',
      B: '인증 · 권한(IAM)',
      C1: '임계값 규칙',
      C2: '승인 정책 규칙',
      D: 'Contexa',
    };
    for (const key of ['A', 'B', 'C1', 'C2', 'D']) {
      const score = control(key);
      const row = within(table)
        .getByRole('rowheader', { name: names[key] ?? key })
        .closest('tr');
      expect(row).toHaveTextContent(`미탐 ${score.missed} · 오탐 ${score.falseBlock.hits}`);
    }
    const totals = full.blindSpot.totals;
    expect(
      screen.getAllByText(`실행 ${totals.attackAllPassed} / ${totals.attackRuns}`).length,
    ).toBeGreaterThan(0);
    expect(
      await screen.findByText(
        `근거 ${decision.quality.reasonMatch.hits} / ${decision.quality.reasonMatch.total}`,
      ),
    ).toBeInTheDocument();
  });

  it('rates every control with its range, and counts the group the visitor chooses (ST-64)', async () => {
    serve();
    const first = open('/validation?tab=controls');
    const rates = await screen.findByRole('table', { name: '보안 통제별 탐지율 · 오탐률' });
    const contexa = control('D');
    expect(
      within(rates).getAllByText(`${contexa.stoppedAny.hits} / ${contexa.stoppedAny.total}`, { exact: false })
        .length,
    ).toBeGreaterThan(0);
    expect(screen.getByText(/AI 판정 전에 인증 · 권한이 먼저 거절한/)).toBeInTheDocument();
    first.unmount();
    serve();
    open('/validation?tab=controls&suite=RULE_BLIND');
    const suite = full.suites.find((candidate) => candidate.suite === 'RULE_BLIND');
    const inSuite = suite?.controls.find((score) => score.control === 'D');
    const table = await screen.findByRole('table', { name: '보안 통제별 탐지율 · 오탐률' });
    expect(
      within(table).getAllByText(`${inSuite?.stoppedAny.hits} / ${inSuite?.stoppedAny.total}`, {
        exact: false,
      }).length,
    ).toBeGreaterThan(0);
    // The static refusals are counted over every scenario: a named group does not state them.
    expect(screen.queryByText(/AI 판정 전에 인증 · 권한이 먼저 거절한/)).not.toBeInTheDocument();
  });

  it('opens a scenario beside the list with what handling it right means, and says one the record lacks (ST-62)', async () => {
    serve();
    const first = open('/validation?tab=scenarios&case=S13');
    const panel = await screen.findByRole('complementary');
    const definition = cases.cases.find((row) => row.key === 'S13');
    const words: Record<string, string> = {
      ALLOW: '허용',
      CHALLENGE: '추가 인증',
      ESCALATE: '검토 보류',
      BLOCK: '차단',
    };
    for (const action of definition?.allowedActions ?? []) {
      expect(await within(panel).findByText(words[action] ?? action)).toBeInTheDocument();
    }
    const row = full.cases.find((candidate) => candidate.key === 'S13');
    const run = row?.runIds[0] ?? 'missing';
    expect(within(panel).getByRole('link', { name: run })).toHaveAttribute('href', `/runs/${run}`);
    first.unmount();
    serve();
    open('/validation?tab=scenarios&case=NOPE');
    expect(await screen.findByText('이 기록에는 이 시나리오가 없습니다.')).toBeInTheDocument();
  });

  it('lists the scenarios the rules do not know first, and only those Contexa got wrong on request', async () => {
    serve();
    open('/validation?tab=scenarios');
    const groups = await screen.findAllByRole('heading', { level: 3 });
    expect(groups[0]).toHaveTextContent('규칙이 미리 모르는 시나리오');
    await userEvent.click(screen.getByRole('switch', { name: 'Contexa가 틀린 실행이 있는 시나리오만' }));
    const wrong = full.cases.filter((row) => row.contexaWrong).length;
    await waitFor(() => expect(screen.getAllByRole('rowheader')).toHaveLength(wrong));
  });

  it('tells how the attacks ended, how long a decision took, and the published prompt checks (ST-59)', async () => {
    serve();
    const first = open('/validation?tab=quality');
    expect(
      await screen.findByRole('heading', { name: `위협 ${full.scope.attackRuns}회 판정 결과` }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText('판정 시간 구간별 판정 수').querySelectorAll('li')).toHaveLength(
      full.engine.analysisBins.length,
    );
    expect(screen.getByText(`그 밖 ${full.judgmentTiming.OTHER}회는 이렇게 끝났습니다`)).toBeInTheDocument();
    const checks = await screen.findByRole('table', { name: 'AI에게 보낸 글(프롬프트) 검사' });
    expect(within(checks).getAllByRole('row')).toHaveLength(8);
    first.unmount();
    serve({ '/api/benchmark/prompt-quality': 404 });
    open('/validation?tab=quality');
    expect(await screen.findByText('아직 공개한 기록이 없어 보여 드릴 값이 없습니다.')).toBeInTheDocument();
  });

  it('counts the agent runs by path, and says a failed read (ST-61)', async () => {
    serve();
    const first = open('/validation?tab=agent');
    expect(
      await screen.findByText(
        `기존 통제 네 곳이 모두 통과시킨 공격 ${agent.total.existingMissed}건 중 Contexa가 ${agent.total.contexaStopped}건(${(agent.total.contexaShare * 100).toFixed(1)}%)을 막았습니다.`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole('table', { name: '에이전트 시나리오 결과' }).querySelectorAll('tbody tr')).toHaveLength(
      agent.byPath.length + 1,
    );
    first.unmount();
    serve({ '/api/benchmark/agent': 500 });
    open('/validation?tab=agent');
    expect(await screen.findByText('에이전트 측정 결과를 불러오지 못했습니다.')).toBeInTheDocument();
  });

  it('names the scenarios Contexa missed every time, with the reason it wrote', async () => {
    serve();
    open('/validation?tab=limits');
    const names = full.missedEveryRunCases.map(
      (key) => full.cases.find((row) => row.key === key)?.title.ko ?? key,
    );
    expect(await screen.findByText(new RegExp(`모두 통과시킨 공격 ${names.length}가지`))).toBeInTheDocument();
    const reason = full.wrongRuns.find(
      (run) => run.caseKey === full.missedEveryRunCases[0] && run.reasoning,
    )?.reasoning;
    if (reason) {
      expect(screen.getByText(reason, { exact: false })).toBeInTheDocument();
    }
  });

  it('shows how the record was made, every notice, another setting to choose and the raw record', async () => {
    serve();
    open('/validation?tab=method');
    const notices = await screen.findByRole('region', { name: '공정하게 보기 위한 안내' });
    expect(within(notices).getAllByRole('listitem')).toHaveLength(full.notices.length);
    expect(
      screen.getByRole('combobox', { name: '다른 설정의 기록' }).querySelectorAll('option'),
    ).toHaveLength(full.specs.length);
    expect(screen.getByRole('link', { name: /기록 전체 내려받기/ })).toHaveAttribute(
      'href',
      '/api/benchmark/runs',
    );
  });

  it('says a measurement that cannot be read and one not made yet (ST-54, ST-55)', async () => {
    serve({ '/api/benchmark': 500 });
    const first = open('/validation');
    expect(await screen.findByText('측정 기록을 불러오지 못했습니다.')).toBeInTheDocument();
    first.unmount();
    serve({ '/api/benchmark': { ...full, spec: null } });
    open('/validation');
    expect(await screen.findByText('아직 측정 기록이 없습니다.')).toBeInTheDocument();
  });
});
