import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EngineCall, JourneyView, PredictionScore } from '../../../api/journey';
import type { LabCase } from '../../../api/lab';
import type { CaseResult, RunScore } from '../../../api/types';
import type { ControlId } from '../../../domain/verdict';
import '../../../i18n';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { required } from '../../../test/required';
import type { Role } from '../experience';
import { ResultStep } from './ResultStep';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

// The try's run, the server's scores by run, the visitor's journey and the first screen's record, set per test.
const tried = vi.hoisted(() => ({
  runId: '',
  scores: {} as Record<string, unknown>,
  journey: null as unknown,
  hook: null as unknown,
}));
vi.mock('./tryRun', () => ({
  useTryRun: () => ({
    pending: false,
    view: { runId: tried.runId, status: 'COMPLETED', steps: [] },
    stored: true,
    runId: tried.runId,
  }),
  useTryAnalysis: () => ({ decision: null, stages: null, wait: null, missing: false }),
}));
vi.mock('../../../api/queries', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../api/queries')>()),
  useRunScore: (runId: string | null) => ({ data: runId ? tried.scores[runId] : undefined }),
}));
vi.mock('../../../api/journey', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../api/journey')>()),
  useJourney: () => ({ data: tried.journey }),
}));
vi.mock('../../../api/hook', () => ({
  useHook: () => ({ data: tried.hook }),
}));

/** A run's score as the portal gives it (this test's own values): each approach's result and data out. */
function scoreOf(
  runId: string,
  scenarioKey: string,
  business: Readonly<Record<ControlId, readonly [CaseResult, number]>>,
  correct: Partial<Record<ControlId, boolean>>,
  finalAction: string,
): RunScore {
  return {
    runId,
    scenarioKey,
    scenarioVersion: 1,
    status: 'COMPLETED',
    truthSource: 'RUN_SNAPSHOT',
    truth: { classification: scenarioKey === 'A3' ? 'THREAT' : 'NORMAL', allowedEngineActions: [] },
    definedSteps: 1,
    executedSteps: 1,
    business: Object.fromEntries(
      Object.entries(business).map(([control, [result, items]]) => [
        control,
        { result, exposedItems: items, worstStep: 1 },
      ]),
    ) as RunScore['business'],
    correct,
    rightControls: 0,
    verdicts: [
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
    ],
    checks: [],
    title: null,
  };
}

const ATTACK = scoreOf(
  'run-a3',
  'A3',
  { A: ['MISSED', 4831], B: ['MISSED', 4831], C1: ['STOPPED', 0], C2: ['STOPPED', 0], D: ['STOPPED', 0] },
  { A: false, B: false, C1: true, C2: true, D: true },
  'ESCALATE',
);
const WORK = scoreOf(
  'run-a3t',
  'A3T',
  { A: ['PASSED', 4831], B: ['PASSED', 4831], C1: ['HALTED', 0], C2: ['PASSED', 4831], D: ['PASSED', 4831] },
  { A: true, B: true, C1: false, C2: true, D: true },
  'ALLOW',
);

/** The visitor's pick as the server scored it against a run (P-4). */
function pick(
  experience: 'E1' | 'E2',
  engine: EngineCall,
  runId: string | null,
  sameAction: boolean | null,
  sameStop: boolean | null,
): PredictionScore {
  return {
    experience,
    caseKey: experience === 'E1' ? 'A3' : 'A3T',
    call: { experience, engine },
    engineRight: null,
    existingActual: null,
    numberRuleActual: null,
    runId,
    engineActual: runId === null ? null : experience === 'E1' ? 'ESCALATE' : 'ALLOW',
    engineSameAction: sameAction,
    engineSameStop: sameStop,
  };
}

function journeyOf(predictions: readonly PredictionScore[], ownA3: boolean): JourneyView {
  return {
    state: { route: 'DEFAULT', act: 1, step: 'e1-result', differences: [], predictions: {}, updatedAt: '' },
    runs: ownA3
      ? [
          {
            runId: 'run-a3',
            scenarioKey: 'A3',
            classification: 'THREAT',
            status: 'COMPLETED',
            lab: false,
            business: {},
            engineAction: 'ESCALATE',
            exposedItems: 0,
            correct: true,
            requestedItems: 4831,
            steps: 1,
          },
        ]
      : [],
    predictions,
  };
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(null, { status: 404 })),
  );
  Object.assign(tried, { scores: { 'run-a3': ATTACK, 'run-a3t': WORK }, hook: null });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function result(role: Role, see = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const key = role === 'attacker' ? 'A3' : 'A3T';
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/try/${role}/result`]}>
        <ResultStep
          role={role}
          mode="sync"
          labCase={{ key, requests: [{}] } as unknown as LabCase}
          see={see}
          flow={{ back: null, next: null, teaser: null }}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const table = screen.getByRole('table');
  // The body rows in the approaches' order: A, B, C1, C2, D.
  const rows = within(table).getAllByRole('row').slice(1);
  return { table, rows };
}

/** The visitor's prediction line under the title, or null when it is not drawn. */
function predictionLine(): HTMLElement | null {
  return screen.queryByText(word('p1.result.mine.label'))?.closest('p') ?? null;
}

const SENTENCES = ['p1.result.mine.same', 'p1.result.mine.sameStop', 'p1.result.mine.other'] as const;

/** 1-4 and 2-3: the prediction line is the sentence the server's comparison picks (F-5); the screen compares nothing. */
describe('the prediction line', () => {
  it.each([
    ['the same judgment', 'ESCALATE', true, true, 'p1.result.mine.same'],
    ['another judgment that also keeps the data in', 'BLOCK', false, true, 'p1.result.mine.sameStop'],
    ['another handling', 'ALLOW', false, false, 'p1.result.mine.other'],
  ] as const)('says %s from the server values', (_, engine, sameAction, sameStop, sentence) => {
    Object.assign(tried, {
      runId: 'run-a3',
      journey: journeyOf([pick('E1', engine, 'run-a3', sameAction, sameStop)], true),
    });
    result('attacker');
    const line = required(predictionLine(), 'prediction line');
    expect(line).toHaveTextContent(word(sentence));
    for (const other of SENTENCES.filter((key) => key !== sentence)) {
      expect(line).not.toHaveTextContent(word(other));
    }
    // The pick is named with the same judgment word as the table.
    const label = {
      ALLOW: 'verdict.allow',
      CHALLENGE: 'verdict.verify',
      ESCALATE: 'verdict.review',
      BLOCK: 'verdict.block',
    }[engine];
    expect(within(line).getByText(word(label))).toBeInTheDocument();
  });

  it('is not drawn before the server compared the pick with this very run', () => {
    Object.assign(tried, {
      runId: 'run-a3',
      journey: journeyOf([pick('E1', 'BLOCK', null, null, null)], true),
    });
    result('attacker');
    expect(predictionLine()).toBeNull();
  });

  it("uses the real employee's pick on 2-3", () => {
    Object.assign(tried, {
      runId: 'run-a3t',
      journey: journeyOf(
        [pick('E1', 'BLOCK', 'run-a3', false, true), pick('E2', 'CHALLENGE', 'run-a3t', false, true)],
        true,
      ),
    });
    result('owner');
    const line = required(predictionLine(), 'prediction line');
    expect(within(line).getByText(word('verdict.verify'))).toBeInTheDocument();
    expect(line).toHaveTextContent(word('p1.result.mine.sameStop'));
  });
});

/** 1-4 (T5): one table of approach, result and data out; the old devices are gone. */
describe('the result of try 1', () => {
  it('draws one table with the server-scored words and nothing of the old screen', () => {
    Object.assign(tried, { runId: 'run-a3', journey: journeyOf([], true) });
    const { table, rows } = result('attacker');

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
      word('e1.result.headline.STOPPED.ESCALATE'),
    );
    expect(screen.getAllByRole('table')).toHaveLength(1);
    expect(
      within(table)
        .getAllByRole('columnheader')
        .map((head) => head.textContent),
    ).toEqual([
      word('e1.result.table.approach'),
      word('e1.result.table.result'),
      word('e1.result.table.out'),
    ]);
    expect(rows).toHaveLength(5);
    // A miss is said as a miss and marked, a right stop as a right stop; Contexa's row also carries its judgment.
    const row = (index: number) => required(rows[index], `row ${index}`);
    for (const missed of [row(0), row(1)]) {
      expect(within(missed).getByText(word('p1.result.word.MISSED'))).toHaveAttribute('data-wrong');
      expect(missed).toHaveTextContent('4,831');
    }
    for (const stopped of [row(2), row(3)]) {
      expect(within(stopped).getByText(word('p1.result.word.STOPPED'))).not.toHaveAttribute('data-wrong');
    }
    const contexa = row(4);
    expect(within(contexa).getByText(word('verdict.review'))).toBeInTheDocument();
    expect(within(contexa).getByText(word('p1.result.word.STOPPED'))).toBeInTheDocument();

    // Gone: the right-answer column and its marks, the folds, the measured line (and their old words).
    const page = document.body;
    for (const old of ['정답', '맞음', '틀림', '측정', '같은 조건', '판정']) {
      expect(page).not.toHaveTextContent(old);
    }
    expect(page.querySelector('details, summary')).toBeNull();
    // One details chip and one source line, nothing else to press in the body.
    expect(screen.getAllByRole('button', { name: word('frame.detail') })).toHaveLength(1);
    expect(page).toHaveTextContent(word('frame.source.run'));
    expect(screen.getAllByRole('button')).toHaveLength(2);
  });
});

/** 2-3 (T5): the two cases side by side in one table. */
describe('the result of try 2', () => {
  it('sets the two cases side by side and marks the work the limits stopped', () => {
    const see = vi.fn();
    Object.assign(tried, { runId: 'run-a3t', journey: journeyOf([], true) });
    const { table, rows } = result('owner', see);

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
      word('e2.result.headline.PASSED_RULE_HALTED'),
    );
    expect(
      within(table)
        .getAllByRole('columnheader')
        .map((head) => head.textContent),
    ).toEqual([
      word('e1.result.table.approach'),
      word('p2.result.table.attacker'),
      word('p2.result.table.owner'),
    ]);
    // A row's cells are the two cases; the approach's name is the row's header.
    const [attackerCell, ownerCell] = within(required(rows[2], 'limits row')).getAllByRole('cell');
    expect(
      within(required(attackerCell, 'attacker cell')).getByText(word('p1.result.word.STOPPED')),
    ).toBeInTheDocument();
    expect(
      within(required(ownerCell, 'owner cell')).getByText(word('p1.result.word.HALTED')),
    ).toHaveAttribute('data-wrong');
    const contexa = required(rows[4], 'contexa row');
    expect(within(contexa).getByText(word('verdict.review'))).toBeInTheDocument();
    expect(within(contexa).getByText(word('verdict.allow'))).toBeInTheDocument();
    expect(within(contexa).getByText(word('p1.result.word.PASSED'))).toBeInTheDocument();
    expect(see).toHaveBeenCalledWith(3);
    // The footnote on the approval rule is gone with the other notes.
    expect(document.body).not.toHaveTextContent('*');
  });

  it('names the recorded run when the visitor skipped try 1', () => {
    Object.assign(tried, {
      runId: 'run-a3t',
      journey: journeyOf([], false),
      hook: { attacker: { runId: 'run-a3' } },
    });
    const { table } = result('owner');
    expect(
      within(table).getByRole('columnheader', { name: word('p2.result.table.attackerRecord') }),
    ).toBeInTheDocument();
  });
});
