import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Pair } from '../api/types';
import i18n from '../i18n';
import ko from '../i18n/ko.json';
import { replayFixture } from '../test/replayFixture';
import { required } from '../test/required';
import ReplayPage from './ReplayPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

/** The old column of the term table (설계서 43~45장, 최종화면-구현계획 F3-6): words the record page no longer shows. */
const BANNED = [
  '계정을 훔친 사람',
  '진짜 직원',
  '본인 확인',
  '규칙 조여 보기',
  '정상 업무 막음',
  '업무를 막음',
  '평소 모습',
  '시간·건수 제한',
  '웹 방화벽',
  '로그인·권한 확인',
  '결재·담당 확인',
  '판정 자세히 보기',
  '응답 전에 막기',
  '다음 요청부터 막기',
  '보류(관리자 검토)',
  '출처 문장',
];

type Answer = { readonly status: number; readonly body: unknown };

let answers: Record<string, Answer>;

function ok(body: unknown): Answer {
  return { status: 200, body };
}

const MISSING: Answer = { status: 404, body: null };

type Result =
  'STOPPED' | 'PARTLY_STOPPED' | 'MISSED' | 'PASSED' | 'PASSED_AFTER_CHECK' | 'HALTED' | 'UNRESOLVED';

/** A stored run's score as the portal returns it: each approach's result and items out, Contexa's judgment. */
function score(
  runId: string,
  classification: 'THREAT' | 'NORMAL',
  business: Readonly<Record<'A' | 'B' | 'C1' | 'C2' | 'D', readonly [Result, number]>>,
  correct: Readonly<Record<string, boolean>>,
  finalAction: string | null,
  steps = 1,
) {
  return {
    runId,
    scenarioKey: 'X',
    scenarioVersion: 1,
    status: 'COMPLETED',
    truthSource: 'RUN_SNAPSHOT',
    truth: { classification, allowedEngineActions: [] },
    definedSteps: steps,
    executedSteps: steps,
    business: Object.fromEntries(
      Object.entries(business).map(([control, [result, exposedItems]]) => [
        control,
        { result, exposedItems, worstStep: null },
      ]),
    ),
    correct,
    rightControls: 1,
    verdicts: finalAction
      ? [
          {
            score: {
              stepNo: 1,
              finalAction,
              result: 'RIGHT',
              applicable: true,
              friction: false,
              applied: 'BEFORE_RESPONSE',
            },
            source: 'MODEL',
            proposedAction: finalAction,
          },
        ]
      : [],
    checks: [],
    title: { ko: '내부자 대량 반출', en: 'Insider bulk export' },
  };
}

const ATTACK = score(
  'run-0000000000a1',
  'THREAT',
  { A: ['MISSED', 4831], B: ['MISSED', 4831], C1: ['STOPPED', 0], C2: ['STOPPED', 0], D: ['STOPPED', 0] },
  { A: false, B: false, C1: true, C2: true, D: true },
  'CHALLENGE',
);
const OWNER = score(
  'run-0000000000b2',
  'NORMAL',
  { A: ['PASSED', 4831], B: ['PASSED', 4831], C1: ['HALTED', 0], C2: ['PASSED', 4831], D: ['PASSED', 4831] },
  { A: true, B: true, C1: false, C2: true, D: true },
  'ALLOW',
);

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  answers = {};
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, Answer> = {
        '/api/visitor': ok({ predictions: {} }),
        '/api/journey': ok({
          state: { route: 'DEFAULT', act: 0, step: 'hook', differences: [] },
          runs: [],
          predictions: [],
        }),
        ...answers,
      };
      const { status, body } = bodies[url] ?? MISSING;
      return new Response(body === null ? null : JSON.stringify(body), { status });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
}

function open(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/replay/:pairKey" element={<ReplayPage />} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function zone(container: HTMLElement, name: string): HTMLElement {
  return required(container.querySelector<HTMLElement>(`[data-zone="${name}"]`), name);
}

/** The cells of one approach's row, in column order. */
function row(container: HTMLElement, control: string): readonly string[] {
  const head = within(zone(container, 'body')).getByRole('rowheader', {
    name: word(`control.${control}.name`),
  });
  return Array.from(
    required(head.closest('tr'), control).querySelectorAll('td'),
    (cell) => cell.textContent ?? '',
  );
}

/** The stored real record (D-35, 화면재편-구현계획 5절 RO-5) in the shared frame. */
describe('the stored real record', () => {
  it("shows a recorded pair's two runs side by side, every cell the run's own score", async () => {
    answers = {
      '/api/replays/A3': ok(replayFixture),
      '/api/runs/run-0000000000a1/score': ok(ATTACK),
      '/api/runs/run-0000000000b2/score': ok(OWNER),
    };
    const { container } = open('/replay/A3');
    // V-18: each column is named by its situation, with that situation's own line.
    const situations = await screen.findByRole('list', { name: word('space.r7.replay.situations') });
    expect(Array.from(situations.querySelectorAll('li'), (item) => item.textContent)).toEqual([
      `${word('space.r7.replay.col.ATTACK')} ${required(replayFixture.scenes[0]).sentence.ko}`,
      `${word('space.r7.replay.col.LEGITIMATE')} ${required(replayFixture.scenes[1]).sentence.ko}`,
    ]);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('space.r7.replay.title'));
    expect(screen.getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual([
      word('e1.result.table.approach'),
      word('space.r7.replay.col.ATTACK'),
      word('space.r7.replay.col.LEGITIMATE'),
    ]);
    expect(row(container, 'A')).toEqual([word('p1.result.word.MISSED'), word('p1.result.word.PASSED')]);
    expect(row(container, 'C1')).toEqual([word('p1.result.word.STOPPED'), word('p1.result.word.HALTED')]);
    // Contexa's judgment of each run, then its result in plain words.
    expect(row(container, 'D')).toEqual([
      `${word('verdict.verify')}${word('p1.result.word.STOPPED')}`,
      `${word('verdict.allow')}${word('p1.result.word.PASSED')}`,
    ]);
    // Both runs agreed in all five repeated sends, as recorded: the source line says so once.
    expect(zone(container, 'source')).toHaveTextContent(fill('space.r7.replay.sourceSame', { runs: 5 }));
    // V-18: a recording whose runs are not of the current measurement says so, with the day it was made.
    await waitFor(() =>
      expect(zone(container, 'source')).toHaveTextContent(fill('space.r7.replay.earlier', { date: '2026-10-05' })),
    );
    // One "see details" per run, each naming whose run it opens; nothing else to press in the screen.
    const details = within(zone(container, 'body')).getAllByRole('button');
    expect(details.map((button) => button.textContent)).toEqual([
      fill('space.r7.replay.detailOf', { who: word('space.r7.replay.col.ATTACK') }),
      fill('space.r7.replay.detailOf', { who: word('space.r7.replay.col.LEGITIMATE') }),
    ]);
    expect(
      within(zone(container, 'actions')).getByRole('link', { name: word('replay2.home') }),
    ).toHaveAttribute('href', '/');
    expect(zone(container, 'top')).toHaveTextContent(word('frame.space.replay'));
    // The situation's title from the record is not shown, nor any old term.
    const text = zone(container, 'body').textContent ?? '';
    for (const banned of BANNED) {
      expect(text, banned).not.toContain(banned);
    }
  });

  it('says how often the repeated sends agreed, as recorded', async () => {
    const pair: Pair = {
      ...replayFixture,
      scenes: [
        { ...required(replayFixture.scenes[0]), agreeing: 2, repetitions: 3 },
        { ...required(replayFixture.scenes[1]), agreeing: 3, repetitions: 3 },
      ],
    };
    answers = {
      '/api/replays/A3': ok(pair),
      '/api/runs/run-0000000000a1/score': ok(ATTACK),
      '/api/runs/run-0000000000b2/score': ok(OWNER),
    };
    const { container } = open('/replay/A3?from=%2Ftry%2Fattacker%2Fpredict');
    expect(await screen.findByRole('table')).toBeInTheDocument();
    expect(zone(container, 'source')).toHaveTextContent(
      `${word('space.r7.replay.source')} · ${word('space.r7.replay.col.ATTACK')}: ${fill('space.r7.replay.repeat.some', { runs: 3, same: 2 })}, ${word('space.r7.replay.col.LEGITIMATE')}: ${fill('space.r7.replay.repeat.same', { runs: 3 })}`,
    );
    // The way back leads to the screen the visitor came from.
    expect(screen.getByRole('link', { name: word('replay2.back') })).toHaveAttribute(
      'href',
      '/try/attacker/predict',
    );
  });

  it('names the day of the current measurement when the recorded runs are of it', async () => {
    const measured = (caseKey: string, runId: string, startedAt: string) =>
      ok({
        caseKey,
        settingHash: 's',
        protocolId: 'protocol-now',
        runs: 2,
        results: { STOPPED: 2 },
        allSame: true,
        analysisMs: null,
        exposedItems: null,
        list: [
          { runId: 'run-other', startedAt: '2026-10-19T09:00:00Z', result: 'STOPPED', engineAction: 'BLOCK', analysisMs: 1, exposedItems: 0, reissueOutcome: null, releaseMillis: null, responseMs: 1 },
          { runId, startedAt, result: 'STOPPED', engineAction: 'BLOCK', analysisMs: 1, exposedItems: 0, reissueOutcome: null, releaseMillis: null, responseMs: 1 },
        ],
        resumed: null,
        responseMs: null,
        middleRun: runId,
      });
    answers = {
      '/api/replays/A3': ok(replayFixture),
      '/api/runs/run-0000000000a1/score': ok({ ...ATTACK, scenarioKey: 'A3' }),
      '/api/runs/run-0000000000b2/score': ok({ ...OWNER, scenarioKey: 'A3T' }),
      '/api/cases/A3/measured': measured('A3', 'run-0000000000a1', '2026-10-20T11:47:48Z'),
      '/api/cases/A3T/measured': measured('A3T', 'run-0000000000b2', '2026-10-20T11:50:18Z'),
    };
    const { container } = open('/replay/A3');
    expect(await screen.findByText(fill('space.r7.replay.measured', { date: '2026-10-20' }), { exact: false })).toBeInTheDocument();
    expect(zone(container, 'source')).not.toHaveTextContent(fill('space.r7.replay.earlier', { date: '2026-10-05' }));
  });

  it("shows a situation without a recording from its current repeated sends' middle run", async () => {
    answers = {
      '/api/replays/A6T': MISSING,
      '/api/cases/A6T/measured': ok({
        caseKey: 'A6T',
        settingHash: 's',
        protocolId: 'protocol-1',
        runs: 3,
        results: { PASSED: 2, PASSED_AFTER_CHECK: 1 },
        allSame: false,
        analysisMs: null,
        exposedItems: null,
        list: [],
        resumed: null,
        responseMs: null,
        middleRun: 'run-0000000000b2',
      }),
      '/api/runs/run-0000000000b2/score': ok({ ...OWNER, executedSteps: 5, definedSteps: 5 }),
    };
    const { container } = open('/replay/A6T');
    expect(await screen.findByText(word('space.r7.replay.expected.NORMAL'))).toBeInTheDocument();
    // A run of five requests: no judgment chip of the first request beside the whole run's result.
    expect(row(container, 'D')).toEqual([
      word('p1.result.word.PASSED'),
      fill('e1.result.items', { items: '4,831' }),
    ]);
    expect(row(container, 'C1')).toEqual([
      word('p1.result.word.HALTED'),
      fill('e1.result.items', { items: '0' }),
    ]);
    expect(screen.getByText(fill('space.r7.replay.steps', { n: 5 }))).toBeInTheDocument();
    expect(zone(container, 'source')).toHaveTextContent(
      `${word('space.r7.replay.source')} · ${fill('space.r7.replay.repeat.afterCheck', { runs: 3, n: 1 })}`,
    );
    const detail = within(zone(container, 'body')).getByRole('button', { name: word('frame.detail') });
    await userEvent.click(detail);
    expect(screen.getByTestId('where')).toHaveTextContent('run-0000000000b2');
  });

  it('says the record is being prepared when the situation has neither a recording nor repeated sends', async () => {
    answers = { '/api/replays/A3': MISSING, '/api/cases/A3/measured': MISSING };
    const { container } = open('/replay/A3');
    expect(await screen.findByText(word('state.notReady'))).toBeInTheDocument();
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
    expect(container.querySelector('table')).toBeNull();
  });

  it('says the same when a recorded run has no score on the server, instead of waiting forever', async () => {
    answers = { '/api/replays/A3': ok(replayFixture), '/api/runs/run-0000000000a1/score': ok(ATTACK) };
    const { container } = open('/replay/A3');
    expect(await screen.findByText(word('state.notReady'))).toBeInTheDocument();
    expect(container.querySelector('table')).toBeNull();
  });
});
