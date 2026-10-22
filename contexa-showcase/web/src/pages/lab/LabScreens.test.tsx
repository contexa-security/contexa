import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import LabBeforePage from './LabBeforePage';
import LabCasePage from './LabCasePage';
import LabChangePage from './LabChangePage';
import LabEntrancePage from './LabEntrancePage';
import LabResultPage from './LabResultPage';
import LabRulesPage from './LabRulesPage';
import LabSendPage from './LabSendPage';
import { barProgress } from './labPlace';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

const NONE = {
  operation: null,
  target: null,
  items: null,
  ticket: 'NONE',
  claim: null,
  onCall: false,
};

/** The lab's options as the portal returns them (GET /api/lab/options), cut to the cases the tests use. */
const OPTIONS = {
  employees: [
    {
      key: 'adm-a',
      role: 'ADMIN',
      displayName: 'Administrator A',
      department: 'IT',
      officeNetwork: '10.0.0.0/8',
      assignedProjects: [],
      customersManaged: 0,
      roleAllows: {},
    },
  ],
  timeSlots: [
    { slot: 'DAWN', representativeTime: '03:17' },
    { slot: 'AFTERNOON', representativeTime: '14:20' },
  ],
  items: [40, 4831],
  operations: ['EXPORT'],
  cases: [
    {
      key: 'A3',
      classification: 'THREAT',
      title: { ko: '내부자 대량 반출', en: 'Insider bulk export' },
      conditions: {
        ...NONE,
        employee: 'adm-a',
        timeSlot: 'DAWN',
        place: 'OFFICE',
        device: 'USUAL',
        operation: 'EXPORT',
        target: 'UNASSIGNED',
        items: 4831,
        approval: false,
        claim: 'NONE',
      },
      requests: [{}],
    },
    {
      key: 'A6',
      classification: 'THREAT',
      title: { ko: 'A6', en: 'A6' },
      conditions: {
        ...NONE,
        employee: 'adm-a',
        timeSlot: 'AFTERNOON',
        place: 'OFFICE',
        device: 'USUAL',
        approval: false,
      },
      requests: [{}, {}, {}, {}, {}],
    },
    {
      key: 'S07',
      classification: 'UNCERTAIN',
      title: { ko: 'S07', en: 'S07' },
      conditions: {
        ...NONE,
        employee: 'adm-a',
        timeSlot: 'DAWN',
        place: 'OFFICE',
        device: 'USUAL',
        approval: false,
      },
      requests: [{}, {}],
    },
  ],
  calls: ['ATTACK', 'NORMAL', 'UNSURE'],
  assessmentReasons: [],
};

/** What the engine received in a run, as the comparison before sending reads it. */
function received(
  runId: string,
  departures: number,
  flagged: number,
  applies: boolean,
  extra: Readonly<Record<string, unknown>> = {},
) {
  return {
    runId,
    stepNo: 1,
    departureCount: departures,
    companyAdverseCount: flagged,
    boundary: null,
    minimumRules: { rules: [], applies },
    ...extra,
  };
}

/** The cells of a table row, as a visitor reads them. */
function cells(rowName: string): (string | null)[] {
  const row = required(screen.getByText(rowName).closest('tr'), rowName);
  return Array.from(row.querySelectorAll('td'), (cell) => cell.textContent);
}

const LAYERS = {
  A: { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 4831, elapsedMs: 120 },
  B: { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 4831, elapsedMs: 130 },
  C1: { outcome: 'STOPPED', httpStatus: 403, deliveredItems: 0, elapsedMs: 90 },
  C2: { outcome: 'STOPPED', httpStatus: 403, deliveredItems: 0, elapsedMs: 95 },
  D: { outcome: 'STOPPED', httpStatus: 403, deliveredItems: 0, elapsedMs: 5900 },
};

const RULE_DEFAULTS = {
  nightStartHour: 22,
  nightEndHour: 6,
  volumeLimit: 500,
  assignedLimit: 500,
  dormantWindowDays: 30,
  historyWindowDays: 90,
  ruleVersion: 'v',
  settings: {
    nightStartHour: 22,
    nightEndHour: 6,
    volumeLimit: 500,
    dormant: true,
    external: true,
    falseClaim: true,
    approval: true,
    ticket: true,
    assigned: true,
    assignedLimit: null,
    history: true,
  },
};

function tally(attacks: number, stopped: number, normals: number, blocked: number, checked = 0) {
  return {
    attacks,
    attacksStopped: stopped,
    normals,
    normalsBlocked: blocked,
    normalsChecked: checked,
    undecided: 0,
  };
}

interface Server {
  benchmark: unknown;
  designed: unknown;
  composed: unknown;
  live: unknown;
  recent: unknown[];
  versus: unknown;
  delta: unknown;
  ruleResult: { changed: unknown[] } & Record<string, unknown>;
  evaluated: unknown[];
}

const server: Server = {
  benchmark: null,
  designed: null,
  composed: null,
  live: null,
  recent: [],
  versus: null,
  delta: null,
  ruleResult: { changed: [] },
  evaluated: [],
};

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(body === null ? null : JSON.stringify(body), { status }));
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  Object.assign(server, {
    benchmark: { cases: [{ key: 'A3', cells: { D: { right: 4, counted: 5, state: 'MIXED' } } }] },
    designed: null,
    composed: null,
    live: null,
    recent: [],
    versus: null,
    delta: null,
    ruleResult: {
      casesComputedAt: '2026-10-18T09:45:36Z',
      settings: RULE_DEFAULTS.settings,
      tallies: { C1: tally(15, 10, 13, 6), C2: tally(15, 12, 13, 2), D: tally(15, 15, 13, 0, 1) },
      changed: [],
    },
    evaluated: [],
  });
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })),
  );
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        const body = JSON.parse(String(init.body)) as Record<string, unknown>;
        if (url === '/api/lab/before') {
          return json({ comparison: body['conditions'] ? server.composed : server.designed });
        }
        if (url === '/api/rules/evaluate') {
          server.evaluated.push(body);
          return json(server.ruleResult);
        }
        return json(null, 404);
      }
      if (/^\/api\/runs\/[^/]+\/versus/.test(url)) {
        return server.versus ? json(server.versus) : json(null, 404);
      }
      if (/^\/api\/lab\/runs\/[^/]+\/delta$/.test(url)) {
        return server.delta ? json(server.delta) : json(null, 404);
      }
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/lab/options': OPTIONS,
        '/api/benchmark': server.benchmark,
        '/api/live/config': {
          scenarios: [],
          turnstileSiteKey: null,
          dailyRuns: 10,
          remainingToday: 7,
          paused: false,
        },
        '/api/live/runs/current': server.live,
        '/api/lab/runs/recent': server.recent,
        '/api/rules/cases': {
          computedAt: '2026-10-18T09:45:36Z',
          defaults: RULE_DEFAULTS,
          cases: [
            {
              scenario: 'A3',
              classification: 'THREAT',
              title: { ko: '내부자 대량 반출', en: 'x' },
              runId: 'run-1',
            },
            { scenario: 'A6', classification: 'THREAT', title: { ko: 'A6', en: 'A6' }, runId: 'run-2' },
          ],
          recordedFrom: '2026-10-17T11:13:03Z',
          recordedTo: '2026-10-18T09:33:14Z',
        },
      };
      const body = bodies[url];
      return body === undefined || body === null ? json(null, 404) : json(body);
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open(element: ReactElement, path: string) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[path]}>{element}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function zone(container: HTMLElement, name: string): HTMLElement {
  return required(container.querySelector<HTMLElement>(`[data-zone="${name}"]`), name);
}

function heading(): HTMLElement {
  return screen.getByRole('heading', { level: 1 });
}

/** The lab's screens in the redesigned frame (화면재편 R7, RO-2): the space and step on top, one type per screen. */
describe('lab frame', () => {
  it('names the lab and the step in the top bar and marks the screen type', async () => {
    const { container } = open(<LabEntrancePage />, '/lab');
    expect(
      await screen.findByText(`${word('frame.space.lab')} · ${word('lab.r7.step.entrance')}`),
    ).toBeInTheDocument();
    expect(container.querySelector('main')).toHaveAttribute('data-type', 'T1');
    // The old lab band (tab, steps, difference badge) is gone.
    expect(screen.queryByText(word('labBar.name'))).not.toBeInTheDocument();
  });

  // V-30: a step of the walk says where it is in it, as the entrance numbers the steps.
  it("numbers a step of the walk in the top bar, as the entrance's list does", async () => {
    open(<LabBeforePage />, '/lab/before?case=A3');
    expect(
      await screen.findByText(
        `${word('frame.space.lab')} · ${fill('lab.r7.stepOf', { name: word('lab.r7.step.before'), n: '3', total: '5' })}`,
      ),
    ).toBeInTheDocument();
  });
});

// L-24: the rule tightening has no place in the walk, yet its top bar keeps the same height: an empty track.
describe('the top bar of the lab', () => {
  it('fills the track as far as the walk goes and leaves it empty beside the walk', () => {
    expect(barProgress('case')).toBe(33);
    expect(barProgress('result')).toBe(100);
    expect(barProgress('rules')).toBe(0);
  });
});

describe('entrance (T1)', () => {
  // V-30: the entrance names the walk's real steps, the same names and numbers the top bar shows on each screen.
  it('shows the five steps of the walk, what a change reaches with the requests left today, and the rule tightening', async () => {
    const { container } = open(<LabEntrancePage />, '/lab');
    expect(heading()).toHaveTextContent(word('lab.r7.entrance.title'));
    expect(screen.getByText(word('lab.r7.entrance.guide'))).toBeInTheDocument();
    const steps = within(screen.getByRole('list', { name: word('lab.r7.entrance.steps') })).getAllByRole(
      'listitem',
    );
    expect(steps.map((step) => step.textContent)).toEqual([
      `1${word('lab.r7.step.case')}`,
      `2${word('lab.r7.step.change')}`,
      `3${word('lab.r7.step.before')}`,
      `4${word('lab.r7.step.send')}`,
      `5${word('lab.r7.step.result')}`,
    ]);
    expect(await screen.findByText(fill('lab.r7.entrance.remaining', { n: '7' }))).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('lab.r7.entrance.rules') })).toHaveAttribute(
      'href',
      '/lab/rules',
    );
    expect(
      within(zone(container, 'actions')).getByRole('link', { name: word('lab.r7.entrance.next') }),
    ).toHaveAttribute('href', '/lab/case');
  });
});

describe('picking a situation (T3)', () => {
  it('offers every case in one grouped list and waits for a pick', async () => {
    const { container } = open(<LabCasePage />, '/lab/case');
    const list = await screen.findByRole('combobox', { name: word('lab.r7.case.label') });
    const groups = Array.from(list.querySelectorAll('optgroup'), (group) => group.getAttribute('label'));
    expect(groups).toEqual([word('lab.r7.case.group.stop'), word('lab.r7.case.group.none')]);
    expect(within(list).getByRole('option', { name: word('lab.r7.case.name.A3') })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 2 })).not.toBeInTheDocument();
    // L-20: the way on shows as the main button, off until a pick, with the reason beside it.
    const actions = zone(container, 'actions');
    expect(within(actions).getByText(word('lab.r7.case.pickFirst'))).toBeInTheDocument();
    expect(within(actions).getByRole('button', { name: word('lab.r7.case.next') })).toBeDisabled();
    expect(within(actions).queryByRole('link')).toHaveAttribute('href', '/lab');
  });

  it('shows the picked case with what is set in advance and Contexa in the repeated sends', async () => {
    const { container } = open(<LabCasePage />, '/lab/case?case=A3');
    expect(await screen.findByRole('heading', { level: 2 })).toHaveTextContent(word('lab.r7.case.name.A3'));
    expect(screen.getByText(word('lab.r7.case.expect.stop'))).toBeInTheDocument();
    expect(await screen.findByText(fill('lab.r7.case.contexa.stop', { n: '5', k: '4' }))).toBeInTheDocument();
    expect(within(zone(container, 'source')).getByText(word('frame.source.measured'))).toBeInTheDocument();
    expect(
      within(zone(container, 'actions')).getByRole('link', { name: word('lab.r7.case.next') }),
    ).toHaveAttribute('href', '/lab/change?case=A3');
  });

  it('says so when the repeated sends have no record of the case, and counts nothing without a set handling', async () => {
    open(<LabCasePage />, '/lab/case?case=A6');
    expect(await screen.findByText(word('lab.r7.case.contexa.none'))).toBeInTheDocument();
    cleanup();
    const { container } = open(<LabCasePage />, '/lab/case?case=S07');
    expect(await screen.findByText(word('lab.r7.case.contexa.unscored'))).toBeInTheDocument();
    expect(screen.getByText(word('lab.r7.case.expect.none'))).toBeInTheDocument();
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
  });
});

describe('changing one condition (T3)', () => {
  it('asks for a case first when none is picked', async () => {
    open(<LabChangePage />, '/lab/change');
    expect(await screen.findByText(word('lab.r7.change.noCase'))).toBeInTheDocument();
  });

  it("shows the original situation from the case's definition and the one change with the original marked", async () => {
    const { container } = open(<LabChangePage />, '/lab/change?case=A3&field=timeSlot');
    expect(await screen.findByRole('heading', { level: 2 })).toHaveTextContent(
      fill('lab.r7.change.original', { situation: word('lab.r7.case.name.A3') }),
    );
    expect(screen.getByText(fill('lab.slot.DAWN', { time: '03:17' }))).toBeInTheDocument();
    expect(screen.getByText(fill('lab.value.items', { n: '4,831' }))).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: word('lab.r7.change.field') })).toHaveValue('timeSlot');
    const value = screen.getByRole('combobox', { name: word('lab.r7.change.value') });
    expect(
      within(value).getByRole('option', {
        name: fill('lab.r7.change.originalMark', { value: fill('lab.slot.DAWN', { time: '03:17' }) }),
      }),
    ).toBeInTheDocument();
    expect(
      within(zone(container, 'actions')).getByRole('link', { name: word('lab.r7.change.next') }),
    ).toHaveAttribute('href', '/lab/before?case=A3');
  });

  it('keeps the requests of a case of several requests and says so', async () => {
    open(<LabChangePage />, '/lab/change?case=A6');
    expect(await screen.findByText(fill('lab.r7.change.fixed', { n: '5' }))).toBeInTheDocument();
    const field = screen.getByRole('combobox', { name: word('lab.r7.change.field') });
    expect(within(field).queryByRole('option', { name: word('lab.field.items') })).not.toBeInTheDocument();
  });
});

describe('comparison before sending (T2)', () => {
  it('shows what Contexa received before and after the change, from the latest real requests', async () => {
    server.designed = received('run-designed', 3, 1, true);
    server.composed = received('run-composed', 1, 1, false);
    const { container } = open(<LabBeforePage />, '/lab/before?case=A3&timeSlot=AFTERNOON');
    expect(await screen.findByText(word('lab.r7.before.col.before'))).toBeInTheDocument();
    expect(
      screen.getByText(
        fill('lab.r7.before.changed', {
          list: fill('lab.r7.before.change', {
            name: word('lab.field.timeSlot'),
            from: fill('lab.slot.DAWN', { time: '03:17' }),
            to: fill('lab.slot.AFTERNOON', { time: '14:20' }),
          }),
        }),
      ),
    ).toBeInTheDocument();
    // V-29: a value that differs after the change is marked; one that stayed is not.
    expect(cells(word('lab.r7.before.row.usual'))).toEqual([
      fill('lab.r7.before.count', { n: '3' }),
      `${fill('lab.r7.before.count', { n: '1' })}${word('lab.r7.result.changedTag')}`,
    ]);
    expect(cells(word('lab.r7.before.row.company'))).toEqual([
      fill('lab.r7.before.count', { n: '1' }),
      fill('lab.r7.before.count', { n: '1' }),
    ]);
    expect(cells(word('lab.r7.before.row.line'))).toEqual([
      word('lab.r7.before.line.applies'),
      `${word('lab.r7.before.line.clear')}${word('lab.r7.result.changedTag')}`,
    ]);
    expect(screen.getByText(word('lab.r7.before.expect.changed'))).toBeInTheDocument();
    // V-29: each column names its own record.
    const source = zone(container, 'source');
    expect(within(source).getByText(word('lab.r7.before.source.before'))).toBeInTheDocument();
    expect(within(source).getByText(word('lab.r7.before.source.now'))).toBeInTheDocument();
    expect(within(source).getAllByRole('button', { name: word('frame.source.open') })).toHaveLength(2);
  });

  // V-29: the line of the rules names the rule the engine found met; records under different criteria say so.
  it('names the minimum response rule a record met and says when the two records were judged under different criteria', async () => {
    server.designed = { ...received('run-designed', 4, 0, false), minimumRules: null, modelJudges: true };
    server.composed = received('run-composed', 4, 1, true, {
      minimumRules: {
        rules: [
          {
            code: 'MIN_P1_IDENTITY_DEVIATION',
            line: 'P1 MIN_P1_IDENTITY_DEVIATION: x',
            floor: 'CHALLENGE',
            met: false,
          },
          {
            code: 'MIN_P3_POLICY_NOT_SATISFIED',
            line: 'P3 MIN_P3_POLICY_NOT_SATISFIED: x',
            floor: 'ESCALATE',
            met: true,
          },
        ],
        applies: true,
      },
    });
    open(<LabBeforePage />, '/lab/before?case=A3&approval=true');
    expect(await screen.findByText(word('lab.r7.before.col.before'))).toBeInTheDocument();
    expect(cells(word('lab.r7.before.row.line'))).toEqual([
      word('lab.r7.before.line.modelJudges'),
      `${fill('lab.r7.before.line.appliesNamed', {
        names: word('lab.r7.before.rule.MIN_P3_POLICY_NOT_SATISFIED'),
      })}${word('lab.r7.result.changedTag')}`,
    ]);
    expect(screen.getByText(word('lab.r7.before.versionDiffers'))).toBeInTheDocument();
  });

  it('says there is nothing to compare when no request of the changed conditions was sent', async () => {
    server.designed = received('run-designed', 3, 1, true);
    open(<LabBeforePage />, '/lab/before?case=A3&timeSlot=AFTERNOON');
    expect(await screen.findByText(word('lab.r7.before.noRecord'))).toBeInTheDocument();
  });

  it('shows one column and the set handling for the situation sent as it is', async () => {
    server.designed = received('run-designed', 3, 1, true);
    open(<LabBeforePage />, '/lab/before?case=A3');
    expect(await screen.findByText(word('lab.r7.before.col.asIs'))).toBeInTheDocument();
    expect(screen.queryByText(word('lab.r7.before.col.before'))).not.toBeInTheDocument();
    expect(screen.getByText(word('lab.r7.before.guideAsDesigned'))).toBeInTheDocument();
    expect(screen.getByText(word('lab.r7.before.expect.stop'))).toBeInTheDocument();
  });
});

describe('predicting and sending (T3, T4)', () => {
  it('offers three calls and keeps Send off until one is picked', async () => {
    const { container } = open(<LabSendPage />, '/lab/send?case=A3');
    // The action bar appears once the case is read; wait for it before looking inside.
    const send = await within(await waitFor(() => zone(container, 'actions'))).findByRole('button', {
      name: word('lab.r7.send.send'),
    });
    expect(screen.getAllByRole('radio')).toHaveLength(3);
    expect(send).toBeDisabled();
    // L-23: the off button says what turns it on, until a call is picked.
    expect(within(zone(container, 'actions')).getByText(word('lab.r7.send.pickFirst'))).toBeInTheDocument();
    fireEvent.click(screen.getByRole('radio', { name: new RegExp(word('lab.r7.send.call.NORMAL')) }));
    await waitFor(() => expect(send).toBeEnabled());
    expect(screen.queryByText(word('lab.r7.send.pickFirst'))).not.toBeInTheDocument();
    expect(container.querySelector('main')).toHaveAttribute('data-type', 'T3');
  });

  // L-23: the screen says what is about to be sent, so the call is about a known request.
  it('names the situation to send and its change, or that it goes as designed', async () => {
    open(<LabSendPage />, '/lab/send?case=A3&approval=true');
    const line = (await screen.findByText(word('lab.r7.send.what'))).closest('p');
    expect(line).toHaveTextContent(word('lab.r7.case.name.A3'));
    expect(line).toHaveTextContent(
      fill('lab.r7.before.changed', {
        list: fill('lab.r7.before.change', {
          name: word('lab.field.approval'),
          from: word('lab.value.no'),
          to: word('lab.value.yes'),
        }),
      }),
    );
    cleanup();
    open(<LabSendPage />, '/lab/send?case=A3');
    expect((await screen.findByText(word('lab.r7.send.what'))).closest('p')).toHaveTextContent(
      word('lab.r7.send.asDesigned'),
    );
  });

  it("draws the sent run's five answers and leads to the result compared with the previous run", async () => {
    server.live = {
      liveRunId: 'live-1',
      scenario: 'A3',
      status: 'COMPLETED',
      queuePosition: 0,
      queueWaitSeconds: null,
      runId: 'run-new',
      readyMs: 10,
      steps: [{ stepNo: 1, operation: 'EXPORT', layers: LAYERS }],
      challenge: null,
      failure: null,
    };
    server.recent = [
      {
        runId: 'run-old',
        caseKey: 'A3',
        designed: false,
        changed: [],
        conditions: {},
        composedAt: '',
        call: null,
        approaches: {},
      },
    ];
    const { container } = open(<LabSendPage />, '/lab/send?case=A3&sent=live-1');
    const next = await within(await waitFor(() => zone(container, 'actions'))).findByRole('link', {
      name: word('lab.r7.run.next'),
    });
    await waitFor(() => expect(next).toHaveAttribute('href', '/lab/result?run=run-new&against=run-old'));
    // V-04: an ended run is titled as ended, not as still sending.
    expect(heading()).toHaveTextContent(word('lab.r7.run.titleDone'));
    expect(screen.getByText(word('lab.r7.run.guideDone'))).toBeInTheDocument();
    expect(screen.queryByText(word('lab.r7.run.guide'))).not.toBeInTheDocument();
    expect(container.querySelectorAll('[data-control]')).toHaveLength(5);
    expect(screen.getAllByText(fill('e1.run.out', { seconds: '0.12', items: '4,831' }))).toHaveLength(1);
    // T-01: the rules' refusal reads as the result chip "blocked", never "denied".
    expect(screen.getByText(fill('lab.r7.run.denied', { seconds: '0.09' }))).toBeInTheDocument();
    expect(screen.queryByText(fill('e1.run.denied', { seconds: '0.09' }))).not.toBeInTheDocument();
    expect(within(zone(container, 'source')).getByText(word('frame.source.run'))).toBeInTheDocument();
    expect(container.querySelector('main')).toHaveAttribute('data-type', 'T4');
  });

  // V-04: a case of two requests whose run ended after one names no "first request"; a waiting one numbers it.
  it('names the request only when the run has more than one, by its number', async () => {
    const run = {
      liveRunId: 'live-1',
      scenario: 'S07',
      status: 'COMPLETED',
      queuePosition: 0,
      queueWaitSeconds: null,
      runId: 'run-new',
      readyMs: 10,
      steps: [{ stepNo: 1, operation: 'EXPORT', layers: LAYERS }],
      challenge: null,
      failure: null,
    };
    server.live = run;
    const { container } = open(<LabSendPage />, '/lab/send?case=S07&sent=live-1');
    await within(await waitFor(() => zone(container, 'actions'))).findByRole('link', {
      name: word('lab.r7.run.next'),
    });
    expect(screen.queryByText(word('p1.run.request.first'))).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 2 })).not.toBeInTheDocument();
    cleanup();
    server.live = { ...run, status: 'AWAITING', awaitingStep: 2, runId: null };
    open(<LabSendPage />, '/lab/send?case=S07&sent=live-1');
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: fill('lab.r7.run.request', { n: '1', total: '2' }),
      }),
    ).toBeInTheDocument();
    expect(heading()).toHaveTextContent(word('lab.r7.run.title'));
  });

  // L-26: while the request goes out nothing on the screen offers to leave it; once it has ended, the way back returns.
  it('offers no way back while the request is going out, and the way back once it has ended', async () => {
    const run = {
      liveRunId: 'live-1',
      scenario: 'A3',
      status: 'RUNNING',
      queuePosition: 0,
      queueWaitSeconds: null,
      runId: null,
      readyMs: 10,
      steps: [{ stepNo: 1, operation: 'EXPORT', layers: { A: LAYERS.A } }],
      challenge: null,
      failure: null,
    };
    server.live = run;
    const { container } = open(<LabSendPage />, '/lab/send?case=A3&sent=live-1');
    expect(await screen.findByText(word('lab.r7.run.title'))).toBeInTheDocument();
    expect(within(zone(container, 'actions')).queryByRole('link')).toBeNull();
    cleanup();
    server.live = { ...run, status: 'COMPLETED', runId: 'run-new', steps: [{ stepNo: 1, layers: LAYERS }] };
    const ended = open(<LabSendPage />, '/lab/send?case=A3&sent=live-1');
    await within(await waitFor(() => zone(ended.container, 'actions'))).findByRole('link', {
      name: word('lab.r7.run.next'),
    });
    expect(within(zone(ended.container, 'actions')).getByRole('link', { name: word('frame.back') })).toHaveAttribute(
      'href',
      '/lab/change?case=A3',
    );
  });

  it('says the run is gone when the address names a run that is not the current one', async () => {
    server.live = {
      liveRunId: 'live-2',
      scenario: 'A3',
      status: 'COMPLETED',
      queuePosition: 0,
      queueWaitSeconds: null,
      runId: 'run-x',
      readyMs: 1,
      steps: [],
      challenge: null,
      failure: null,
    };
    open(<LabSendPage />, '/lab/send?case=A3&sent=live-1');
    expect(await screen.findByText(word('lab.r7.run.ended'))).toBeInTheDocument();
  });
});

describe('the result compared (T5)', () => {
  it('asks for a send first without a run', async () => {
    open(<LabResultPage />, '/lab/result');
    expect(heading()).toHaveTextContent(word('p1.result.empty'));
    expect(screen.getByText(word('lab.r7.result.noRun'))).toBeInTheDocument();
  });

  it("titles the server's comparison and shows every approach last time and this time", async () => {
    server.versus = {
      before: {
        runId: 'run-old',
        scenarioKey: 'A3',
        business: {},
        outcomes: { A: 'DELIVERED', B: 'DELIVERED', C1: 'STOPPED', C2: 'STOPPED', D: 'DELIVERED' },
        engineAction: 'ALLOW',
        exposedItems: 4831,
      },
      now: {
        runId: 'run-new',
        scenarioKey: 'A3',
        business: {},
        outcomes: { A: 'DELIVERED', B: 'DELIVERED', C1: 'STOPPED', C2: 'STOPPED', D: 'STOPPED' },
        engineAction: 'ESCALATE',
        exposedItems: 0,
      },
      changedControls: ['D'],
      contexaChanged: true,
      changedConditions: ['timeSlot'],
      inputs: [],
    };
    server.recent = [
      {
        runId: 'run-new',
        caseKey: 'A3',
        designed: false,
        changed: ['timeSlot'],
        conditions: {},
        composedAt: '',
        call: 'ATTACK',
        approaches: {},
      },
    ];
    server.delta = {
      runId: 'run-new',
      baseRunId: 'run-old',
      condition: 'timeSlot',
      value: 'AFTERNOON',
      available: true,
      reason: null,
      steps: [
        {
          stepNo: 1,
          changed: [],
          expected: [],
          unexpected: [],
          valueMatches: true,
          passed: true,
          notCompared: null,
        },
      ],
    };
    const { container } = open(<LabResultPage />, '/lab/result?run=run-new&against=run-old');
    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: fill('lab.r7.result.headline.changedOne', {
          condition: word('lab.fieldInline.timeSlot'),
          from: word('verdict.allow'),
          to: word('verdict.review'),
        }),
      }),
    ).toBeInTheDocument();
    // T-01, B-08: without a set handling every answer reads as a result chip of what the data did; Contexa's cell
    // adds its judgment, so a stop by a hold is not read as a block judgment.
    expect(cells(word('control.D.name'))).toEqual([
      `${word('main.lane.allowed')}${fill('lab.r7.result.judged', { verdict: word('verdict.allow') })}`,
      `${word('main.lane.stopped')}${fill('lab.r7.result.judged', { verdict: word('verdict.review') })}${word('lab.r7.result.changedTag')}`,
    ]);
    expect(cells(word('control.A.name'))).toEqual([word('main.lane.allowed'), word('main.lane.allowed')]);
    expect(screen.getByText(fill('lab.r7.result.exposed', { items: '0' }))).toBeInTheDocument();
    expect(await screen.findByText(word('lab.r7.result.delta.passed'))).toBeInTheDocument();
    expect(await screen.findByText(word('lab.r7.send.call.ATTACK'))).toBeInTheDocument();
    // A changed situation has nothing set in advance.
    expect(screen.getByText(word('lab.r7.result.expectNone'))).toBeInTheDocument();
    expect(screen.getByRole('button', { name: word('frame.detail') })).toBeInTheDocument();
    expect(within(zone(container, 'source')).getByText(word('frame.source.run'))).toBeInTheDocument();
    expect(container.querySelector('main')).toHaveAttribute('data-type', 'T5');
  });

  it('shows only this run without an earlier one', async () => {
    server.versus = {
      before: {
        runId: 'run-new',
        scenarioKey: 'A3',
        business: {},
        outcomes: {},
        engineAction: 'BLOCK',
        exposedItems: 0,
      },
      now: {
        runId: 'run-new',
        scenarioKey: 'A3',
        business: {},
        outcomes: { D: 'STOPPED' },
        engineAction: 'BLOCK',
        exposedItems: 0,
      },
      changedControls: [],
      contexaChanged: false,
      changedConditions: [],
      inputs: [],
    };
    open(<LabResultPage />, '/lab/result?run=run-new');
    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: fill('lab.r7.result.headline.only', { verdict: word('verdict.block') }),
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(word('lab.r7.result.guideOnly'))).toBeInTheDocument();
    expect(screen.queryByText(word('lab.r7.result.col.before'))).not.toBeInTheDocument();
  });

  // Review before the guide videos (2026-10-21, B-08): a first send compares with the latest real run of the case and
  // says whether the call was right.
  it('compares a first send with the latest real run of the situation and says whether the call was right', async () => {
    server.versus = {
      before: {
        runId: 'run-ref',
        scenarioKey: 'A3',
        business: {},
        outcomes: { D: 'STOPPED' },
        engineAction: 'BLOCK',
        exposedItems: 0,
      },
      now: {
        runId: 'run-new',
        scenarioKey: 'A3',
        business: {},
        outcomes: { D: 'STOPPED' },
        engineAction: 'BLOCK',
        exposedItems: 0,
      },
      changedControls: [],
      contexaChanged: false,
      changedConditions: [],
      inputs: [],
    };
    server.recent = [
      {
        runId: 'run-new',
        caseKey: 'A3',
        designed: true,
        changed: [],
        conditions: {},
        composedAt: '',
        call: 'ATTACK',
        approaches: {},
        referenceRunId: 'run-ref',
        callRight: true,
      },
    ];
    open(<LabResultPage />, '/lab/result?run=run-new');
    expect(await screen.findByText(word('lab.r7.result.guideReference'))).toBeInTheDocument();
    expect(screen.getByText(word('lab.r7.result.col.reference'))).toBeInTheDocument();
    expect(screen.getByText(word('lab.r7.result.callRight'))).toBeInTheDocument();
  });

  // T-01, B-08: a situation with a set handling shows the server's business results as the deck's result chips,
  // each in its own color, never "cut part-way" or "stopped".
  it("shows a scored run's answers as the result chips, each colored by its kind", async () => {
    server.versus = {
      before: {
        runId: 'run-new',
        scenarioKey: 'A3',
        business: {},
        outcomes: {},
        engineAction: 'BLOCK',
        exposedItems: 2520,
      },
      now: {
        runId: 'run-new',
        scenarioKey: 'A3',
        business: { A: 'MISSED', B: 'MISSED', C1: 'STOPPED', C2: 'STOPPED', D: 'PARTLY_STOPPED' },
        outcomes: { A: 'DELIVERED', B: 'DELIVERED', C1: 'STOPPED', C2: 'STOPPED', D: 'CUT' },
        engineAction: 'BLOCK',
        exposedItems: 2520,
      },
      changedControls: [],
      contexaChanged: false,
      changedConditions: [],
      inputs: [],
    };
    const { container } = open(<LabResultPage />, '/lab/result?run=run-new');
    expect(await screen.findByText(word('lab.r7.result.guideOnly'))).toBeInTheDocument();
    expect(cells(word('control.A.name'))).toEqual([word('main.result.MISSED')]);
    expect(cells(word('control.C1.name'))).toEqual([word('main.result.STOPPED')]);
    expect(cells(word('control.D.name'))).toEqual([
      `${word('main.result.PARTLY_STOPPED')}${fill('lab.r7.result.judged', { verdict: word('verdict.block') })}`,
    ]);
    expect(screen.queryByText(word('outcome.cut'))).not.toBeInTheDocument();
    const kinds = Array.from(container.querySelectorAll('td [data-kind]'), (chip) =>
      chip.getAttribute('data-kind'),
    );
    expect(kinds).toEqual(['bad', 'bad', 'block', 'block', 'auth']);
  });
});

describe('tightening the rules (table)', () => {
  it("decides the recorded cases again with the defaults and shows the server's two counts beside Contexa's", async () => {
    const { container } = open(<LabRulesPage />, '/lab/rules');
    // L-24: the rule's row says it runs with the default values until one is changed.
    const rule = await screen.findByText(fill('lab.r7.rules.rowRuleDefault', { name: word('control.C1.name') }));
    expect(server.evaluated[0]).toEqual(RULE_DEFAULTS.settings);
    const row = required(rule.closest('tr'), 'rule row');
    expect(Array.from(row.querySelectorAll('td'), (cell) => cell.textContent)).toEqual([
      fill('labRules.ofTotal', { k: '10', n: '15' }),
      fill('labRules.ofTotal', { k: '6', n: '13' }),
    ]);
    const contexa = required(screen.getByText(word('lab.r7.rules.rowContexa')).closest('tr'), 'Contexa row');
    expect(Array.from(contexa.querySelectorAll('td'), (cell) => cell.textContent)).toEqual([
      fill('labRules.ofTotal', { k: '15', n: '15' }),
      fill('labRules.ofTotal', { k: '0', n: '13' }),
    ]);
    expect(screen.getByText(fill('lab.r7.rules.checked', { c: '1' }))).toBeInTheDocument();
    // L-24: nothing moved, so the one line says so without a heading over it.
    expect(screen.getByText(word('lab.r7.rules.noChange'))).toBeInTheDocument();
    expect(screen.queryByText(word('lab.r7.rules.changed'))).toBeNull();
    // L-24: a date and time of the source line never break inside.
    const source = zone(container, 'source');
    expect(within(source).getByText('2026-10-17 11:13:03').tagName).toBe('SPAN');
    expect(within(source).getByText('2026-10-18 09:33:14').tagName).toBe('SPAN');
    expect(container.querySelector('main')).toHaveAttribute('data-type', 'table');
    // V-31: the rules are picked by the security they belong to, the fixed rule's own settings only.
    const security = screen.getByRole('combobox', { name: word('lab.r7.rules.control') });
    expect(security).toHaveValue('C1');
    expect(
      within(security)
        .getAllByRole('option')
        .map((option) => option.textContent),
    ).toEqual([word('control.C1.name'), word('control.C2.name')]);
    const knob = screen.getByRole('combobox', { name: word('lab.r7.rules.knob') });
    expect(within(knob).getAllByRole('option')).toHaveLength(4);
    expect(within(knob).queryByRole('option', { name: word('lab.r7.rules.knob.approval') })).toBeNull();
    // V-31: what the counts are out of, above the table, from the server's counts.
    expect(
      screen.getByText(fill('lab.r7.rules.scope', { attacks: '15', normals: '13' })),
    ).toBeInTheDocument();
  });

  it("moves to the other security's settings and starts from its first one", async () => {
    open(<LabRulesPage />, '/lab/rules');
    const security = await screen.findByRole('combobox', { name: word('lab.r7.rules.control') });
    fireEvent.change(security, { target: { value: 'C2' } });
    const knob = screen.getByRole('combobox', { name: word('lab.r7.rules.knob') });
    await waitFor(() => expect(knob).toHaveValue('approval'));
    expect(within(knob).getAllByRole('option')).toHaveLength(7);
    expect(
      await screen.findByText(fill('lab.r7.rules.rowRuleDefault', { name: word('control.C2.name') })),
    ).toBeInTheDocument();
  });

  it('changes one setting from the address and lists the moved situations a page at a time', async () => {
    server.ruleResult = {
      ...server.ruleResult,
      // Six situations moved; the second page shows the fourth to the sixth (A6, A3, A6).
      changed: ['A3', 'A6', 'A3', 'A6', 'A3', 'A6'].map((scenario) => ({
        scenario,
        classification: 'THREAT',
        control: 'C2',
        before: true,
        now: false,
      })),
    };
    open(<LabRulesPage />, '/lab/rules?rule=approval&value=off&page=1');
    expect(
      await screen.findByRole('button', {
        name: fill('lab.r7.rules.page', { from: '4', to: '6', total: '6' }),
      }),
    ).toBeInTheDocument();
    expect(server.evaluated.at(-1)).toEqual({ ...RULE_DEFAULTS.settings, approval: false });
    expect(screen.getByRole('combobox', { name: word('lab.r7.rules.control') })).toHaveValue('C2');
    expect(screen.getByRole('combobox', { name: word('lab.r7.rules.knob') })).toHaveValue('approval');
    expect(screen.getByRole('combobox', { name: word('lab.r7.rules.value') })).toHaveValue('false');
    expect(screen.getAllByText(word('lab.r7.case.name.A3'))).toHaveLength(1);
    expect(screen.getAllByText(word('lab.r7.case.name.A6'))).toHaveLength(2);
    // L-24: a changed value names the rule's row as the visitor's.
    expect(screen.getByText(fill('lab.r7.rules.rowRule', { name: word('control.C2.name') }))).toBeInTheDocument();
    expect(screen.getByText(word('lab.r7.rules.changed'))).toBeInTheDocument();
  });
});
