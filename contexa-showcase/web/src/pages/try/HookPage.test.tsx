import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { VERDICTS, type Verdict } from '../../domain/verdict';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import HookPage from './HookPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

const layer = (control: string, outcome: string, verdict: string | null, items: number) => ({
  control,
  outcome,
  verdict,
  httpStatus: 200,
  ruleId: null,
  reason: null,
  ruleFacts: {},
  evidence: { deliveredItems: items, responseMs: 40, verdict, outcome, unresolved: false },
});

interface Side {
  readonly caseKey: string;
  readonly runId: string;
  readonly verdict: Verdict;
  readonly outcome: string;
  readonly delivered: number;
}

/** The hook as the portal gives it (HookViews): each column's representative run with every approach's layer. */
function hook(attacker: Side, owner: Side, distinguished: boolean) {
  const column = (side: Side) => ({
    caseKey: side.caseKey,
    runId: side.runId,
    startedAt: '2026-10-07T21:31:53Z',
    result: {
      companyTime: '2026-09-30T03:17:00Z',
      layers: [
        layer('A', 'DELIVERED', null, 4831),
        layer('B', 'DELIVERED', null, 4831),
        layer('C1', 'STOPPED', null, 0),
        layer('C2', 'STOPPED', null, 0),
        layer('D', side.outcome, side.verdict, side.delivered),
      ],
    },
    business: null,
    correct: { A: false, B: false, C1: true, C2: true, D: true },
    check: null,
    measurement: { protocolId: 'protocol-1', runs: 3, sameResult: 3, passedAfterCheck: 0, results: {} },
  });
  return { attacker: column(attacker), owner: column(owner), distinguished, textsKeptUntil: null };
}

/** Two records with different values, so a card that shows a constant fails one of them. */
const RECORDS = [
  {
    name: 'held and passed',
    attacker: { caseKey: 'A3', runId: 'run-a', verdict: 'ESCALATE', outcome: 'HELD', delivered: 0 },
    owner: { caseKey: 'A3T', runId: 'run-b', verdict: 'ALLOW', outcome: 'DELIVERED', delivered: 4831 },
    items: { A3: 4831, A3T: 4831 },
    shown: { attacker: '0', owner: '4,831', attackerItems: '4,831', ownerItems: '4,831' },
  },
  {
    name: 'blocked and checked',
    attacker: { caseKey: 'A3', runId: 'run-c', verdict: 'BLOCK', outcome: 'STOPPED', delivered: 0 },
    owner: { caseKey: 'A3T', runId: 'run-d', verdict: 'CHALLENGE', outcome: 'HELD', delivered: 120 },
    items: { A3: 1200, A3T: 1200 },
    shown: { attacker: '0', owner: '120', attackerItems: '1,200', ownerItems: '1,200' },
  },
] as const;

let current: unknown;
let caseItems: Readonly<Record<string, number>> = {};

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })),
  );
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/hook': current,
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 0, step: 'hook', differences: [] },
          runs: [],
          predictions: [],
        },
        '/api/lab/options': {
          employees: [],
          timeSlots: [{ slot: 'DAWN', representativeTime: '03:17' }],
          items: [],
          operations: [],
          cases: Object.entries(caseItems).map(([key, items]) => ({
            key,
            conditions: { timeSlot: 'DAWN' },
            requests: [{ items }],
          })),
          calls: [],
          assessmentReasons: [],
        },
      };
      const body = bodies[url];
      return Promise.resolve(
        new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 }),
      );
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderHook() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <HookPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/**
 * Screen 0, the start (화면재편-기획안 7절 T1): the question, two people with Contexa's recorded judgment and the files
 * that went out, the identity line and one source line; the guide claims the two are told apart only when the
 * measurement does.
 */
// The final screen design (최종화면-구현계획 F0-1) opens this screen at no address any more; its address leads to the
// new flow. The screen and this test are on the deletion list for the user (최종화면-구현계획 4절).
describe.skip('start screen', () => {
  it.each(RECORDS)("shows each person's judgment and files out as recorded ($name)", async (record) => {
    current = hook(record.attacker, record.owner, true);
    caseItems = record.items;
    renderHook();

    const attacker = await screen.findByRole('region', { name: word('p0.attacker.name') });
    expect(
      await within(attacker).findByText(fill('p0.attacker.line', { items: record.shown.attackerItems })),
    ).toBeInTheDocument();
    expect(within(attacker).getByText(word(VERDICTS[record.attacker.verdict].labelKey))).toBeInTheDocument();
    expect(within(attacker).getByText(fill('p0.items', { n: record.shown.attacker }))).toBeInTheDocument();

    const owner = screen.getByRole('region', { name: word('p0.owner.name') });
    expect(
      await within(owner).findByText(fill('p0.owner.line', { items: record.shown.ownerItems })),
    ).toBeInTheDocument();
    expect(within(owner).getByText(word(VERDICTS[record.owner.verdict].labelKey))).toBeInTheDocument();
    expect(within(owner).getByText(fill('p0.items', { n: record.shown.owner }))).toBeInTheDocument();
  });

  it('keeps only the question, the two people, the identity line, the source line and Start', async () => {
    current = hook(RECORDS[0].attacker, RECORDS[0].owner, true);
    caseItems = RECORDS[0].items;
    const { container } = renderHook();
    await screen.findByRole('region', { name: word('p0.attacker.name') });

    expect(screen.getByRole('heading', { level: 1, name: word('screen.0.title') })).toBeInTheDocument();
    expect(screen.getByText(word('identity.line'))).toBeInTheDocument();
    const source = required(container.querySelector<HTMLElement>('[data-zone="source"]'), 'the source line');
    expect(source).toHaveTextContent(word('frame.source.measured'));
    expect(within(source).getAllByRole('button')).toHaveLength(1);
    expect(within(source).getByRole('button', { name: word('frame.source.open') })).toBeInTheDocument();
    // The one way on is the flow's main button; the body holds nothing to press.
    expect(screen.getByRole('link', { name: word('screen.0.next') })).toHaveAttribute(
      'href',
      '/part/1',
    );
    const body = required(container.querySelector<HTMLElement>('[data-zone="body"]'), 'the body');
    expect(body.querySelectorAll('a, button, summary, details, table')).toHaveLength(0);

    // Gone from the start: the five-approach table, right and wrong, the replay and its measured lines, the
    // footnote, the two other ways in and the teaser's question.
    const text = document.body.textContent ?? '';
    for (const key of [
      'control.A.name',
      'control.B.name',
      'control.C1.name',
      'control.C2.name',
      'mark.right',
      'mark.wrong',
      'hook.replay',
      'hook.replayAgain',
      'hook.note',
      'hook.concept',
      'hook.benchmark',
      'hook.question',
      'hook.questionFallback',
      'hook.answer.stop',
      'hook.answer.pass',
    ]) {
      expect(text, key).not.toContain(word(key));
    }
    expect(text).not.toMatch(/\d+회 측정/);
  });

  it('says the two are told apart only when the measurement does', async () => {
    current = hook(RECORDS[0].attacker, RECORDS[0].owner, true);
    caseItems = RECORDS[0].items;
    const first = renderHook();
    await screen.findByRole('region', { name: word('p0.attacker.name') });
    expect(required(first.container.querySelector('[data-guide]'), 'the guide')).toHaveTextContent(
      word('screen.0.guide'),
    );
    cleanup();

    current = hook(RECORDS[0].attacker, RECORDS[0].owner, false);
    const second = renderHook();
    await screen.findByRole('region', { name: word('p0.attacker.name') });
    expect(required(second.container.querySelector('[data-guide]'), 'the guide')).toHaveTextContent(
      word('p0.guide.fallback'),
    );
    expect(screen.queryByText(word('screen.0.guide'))).not.toBeInTheDocument();
  });
});
