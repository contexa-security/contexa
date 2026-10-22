import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EngineHours } from '../../api/types';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import LearnedPage from './LearnedPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

interface Counts {
  /** The engine's own learned count (its baseline's updateCount). */
  readonly learned: number;
  /** How many learning requests were sent, and how many of them passed. */
  readonly sent: number;
  readonly allowed: number;
}

/** The requests sent to teach the template: the first `allowed` passed, the rest got an identity check. */
function requestsOf({ sent, allowed }: Counts) {
  return Array.from({ length: sent }, (_, index) => ({
    no: index + 1,
    companyTime: `2026-09-${String(23 + (index % 5)).padStart(2, '0')}T10:${String(index % 60).padStart(2, '0')}:00Z`,
    operation: 'DOCUMENT_READ',
    method: 'GET',
    path: '/api/documents/PLM-OPS-SPC-00234',
    items: null,
    clientAddress: '10.40.12.10',
    httpStatus: 200,
    finalAction: index < allowed ? 'ALLOW' : 'CHALLENGE',
    unresolved: false,
    identityCheckPassed: null,
    reissueOutcome: null,
  }));
}

/** The baseline card as the portal gives it (BaselineCard.View). */
function cardOf(counts: Counts, hours: EngineHours | null, networks: readonly string[] = ['10.40.12.0/24']) {
  return {
    employeeKey: 'adm-a',
    displayName: 'Administrator A',
    department: 'IT administration',
    templateId: 'tpl-adm-a-1',
    capturedAt: '2026-10-17T07:25:49Z',
    learned: {
      requests: counts.learned,
      hours: Array.from({ length: 24 }, (_, hour) => (hour >= 9 && hour <= 17 ? 2 : 0)),
      weekdays: [5, 4, 5, 5, 5, 0, 0],
      networks,
      devices: ['WINDOWS', 'Chrome/140'],
    },
    taught: {
      reads: 15,
      downloads: 5,
      exports: 5,
      exportItemsMin: 14,
      exportItemsMax: 29,
      projects: { 'PLM-OPS': 25 },
      from: '2026-09-23T11:48:00Z',
      to: '2026-09-29T16:04:00Z',
    },
    requests: requestsOf(counts),
    sent: counts.sent,
    allowed: counts.allowed,
    hours,
  };
}

/** The hour lists and state lines of the engine's latest judgment (null where the prompt had no such line). */
function engineHours(values: Partial<EngineHours> = {}): EngineHours {
  return {
    normalAccessHours: [],
    observedHours: [],
    runId: 'run-9851d7971dd7',
    stepNo: 1,
    companyTime: '2026-09-30T03:17:00Z',
    personalBaselineStatus: null,
    workProfileState: null,
    roleScopeState: null,
    observedScopeSummary: null,
    ...values,
  };
}

const OPTIONS = {
  employees: [{ key: 'adm-a', displayName: 'Administrator A', officeNetwork: '10.40.12.0/24' }],
  projects: [],
  timeSlots: [{ slot: 'DAWN', representativeTime: '03:17' }],
  items: [],
  operations: [],
  cases: [{ key: 'A3', conditions: { employee: 'adm-a', timeSlot: 'DAWN' }, requests: [{ items: 4831 }] }],
  calls: [],
  assessmentReasons: [],
};

let card: unknown;

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
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 3, step: 'g-learned', differences: [] },
          runs: [],
          predictions: [],
        },
        '/api/lab/options': OPTIONS,
        '/api/live/baseline/adm-a': card,
      };
      const body = bodies[url];
      return Promise.resolve(
        new Response(body === undefined || body === null ? null : JSON.stringify(body), {
          status: body ? 200 : 404,
        }),
      );
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/intro/learning/learned']}>
        <LearnedPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function openWindow(): Promise<HTMLElement> {
  await userEvent.click(await screen.findByRole('button', { name: word('p3.learned.open') }));
  return screen.getByRole('dialog');
}

/** Two records with different counts, so a screen that shows a constant or the sent count fails one of them. */
const RECORDS = [
  { name: 'one request checked', counts: { learned: 24, sent: 25, allowed: 24 } },
  { name: 'two requests checked', counts: { learned: 37, sent: 39, allowed: 37 } },
] as const;

/** Screen 3-1 (화면재편 T7, F-4): what Contexa learned, the learned count the engine's own. */
describe('what Contexa learned', () => {
  it.each(RECORDS)(
    'writes the count the engine learned, never the count sent ($name)',
    async ({ counts }) => {
      card = cardOf(counts, engineHours());
      const { container } = open();
      expect(
        await screen.findByRole('heading', {
          level: 2,
          name: fill('p3.learned.hours', { n: String(counts.learned) }),
        }),
      ).toBeInTheDocument();
      const body = required(container.querySelector<HTMLElement>('[data-zone="body"]'), 'the body');
      expect(body.textContent).not.toContain(`${counts.sent}건`);
    },
  );

  it('shows the period, the place, the device and the work as the records hold them', async () => {
    card = cardOf(RECORDS[0].counts, engineHours());
    open();
    const facts = await screen.findByText(word('p3.learned.fact.period'));
    const list = required(facts.closest('dl'), 'the facts');
    expect(
      within(list).getByText(fill('p3.learned.fact.periodValue', { from: '9/23', to: '9/29' })),
    ).toBeInTheDocument();
    expect(
      within(list).getByText(fill('p3.learned.fact.office', { band: '10.40.12.0/24' })),
    ).toBeInTheDocument();
    expect(within(list).getByText(`${word('p3.learned.os.WINDOWS')} · Chrome/140`)).toBeInTheDocument();
    const kinds = ['reads', 'downloads', 'exports']
      .map((kind) => word(`p3.learned.kind.${kind}`))
      .join(' · ');
    expect(
      within(list).getByText(fill('p3.learned.fact.workValue', { projects: 'PLM-OPS', kinds })),
    ).toBeInTheDocument();
  });

  it("names a learned network the office only when it is the employee's office network", async () => {
    card = cardOf(RECORDS[0].counts, engineHours(), ['10.99.0.0/16']);
    open();
    expect(await screen.findByText('10.99.0.0/16')).toBeInTheDocument();
    expect(
      screen.queryByText(fill('p3.learned.fact.office', { band: '10.99.0.0/16' })),
    ).not.toBeInTheDocument();
  });

  it('keeps the chart, the four facts and one chip; the states and the request list wait in the window', async () => {
    card = cardOf(RECORDS[0].counts, engineHours({ personalBaselineStatus: 'ESTABLISHED' }));
    const { container } = open();
    await screen.findByRole('button', { name: word('p3.learned.open') });

    // P-40: the person in the visitor's words (관리자 A), not the record's English display name.
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(fill('screen.3-1.title', { name: word('person.adm-a') }));
    expect(screen.getByRole('heading', { level: 1 })).not.toHaveTextContent('Administrator A');
    expect(screen.getByText(word('screen.3-1.guide'))).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('frame.nextNamed').replace('{{name}}', word('more.name.g-how')) })).toHaveAttribute('href', '/intro/how');
    const source = required(container.querySelector<HTMLElement>('[data-zone="source"]'), 'the source line');
    expect(source).toHaveTextContent(word('frame.source.learned'));
    const body = required(container.querySelector<HTMLElement>('[data-zone="body"]'), 'the body');
    expect(body.querySelectorAll('a, button, summary, details')).toHaveLength(1);
    // The learning states and the table are not on the screen until the window opens.
    expect(screen.queryByText(word('p3.learned.window.value.ESTABLISHED'))).not.toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('opens the window with the counts, the reason of the difference and every request sent', async () => {
    const { counts } = RECORDS[0];
    card = cardOf(counts, engineHours());
    open();
    const dialog = await openWindow();
    expect(
      within(dialog).getByRole('heading', {
        name: fill('p3.learned.window.title', { name: word('person.adm-a') }),
      }),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByText(
        fill('p3.learned.window.counts', { sent: '25', allowed: '24', learned: '24' }),
      ),
    ).toBeInTheDocument();
    expect(within(dialog).getByText(word('p3.learned.window.why'))).toBeInTheDocument();
    const rows = within(dialog).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(counts.sent);
    expect(
      within(required(rows[counts.sent - 1], 'the last row')).getByText(word('verdict.verify')),
    ).toBeInTheDocument();
  });

  it('gives no reason when the learned count is not the passed count; the counts alone stay', async () => {
    card = cardOf({ learned: 20, sent: 25, allowed: 24 }, engineHours());
    open();
    const dialog = await openWindow();
    expect(
      within(dialog).getByText(
        fill('p3.learned.window.counts', { sent: '25', allowed: '24', learned: '20' }),
      ),
    ).toBeInTheDocument();
    expect(within(dialog).queryByText(word('p3.learned.window.why'))).not.toBeInTheDocument();
  });

  it("puts the engine's learning states and hour lists in plain words, and says so where a line is missing", async () => {
    card = cardOf(
      RECORDS[0].counts,
      engineHours({
        personalBaselineStatus: 'ESTABLISHED',
        roleScopeState: 'PROVISIONAL',
        normalAccessHours: [9, 10],
        observedHours: [],
      }),
    );
    open();
    const dialog = await openWindow();
    expect(within(dialog).getByText(word('p3.learned.window.value.ESTABLISHED'))).toBeInTheDocument();
    expect(within(dialog).getByText(word('p3.learned.window.value.PROVISIONAL'))).toBeInTheDocument();
    expect(within(dialog).getByText(word('p3.learned.window.scopeWhy'))).toBeInTheDocument();
    const hour = (n: number) => fill('hourBars.tick', { hour: String(n) });
    expect(within(dialog).getByText(`${hour(9)}, ${hour(10)}`)).toBeInTheDocument();
    expect(within(dialog).getByText(word('p3.learned.window.value.none'))).toBeInTheDocument();
  });

  it('never shows an engine state code; one without plain words is named as another state', async () => {
    card = cardOf(RECORDS[0].counts, engineHours({ personalBaselineStatus: 'SOME_NEW_STATE' }));
    open();
    const dialog = await openWindow();
    expect(dialog.textContent).not.toContain('SOME_NEW_STATE');
    expect(within(dialog).getByText(word('p3.learned.window.value.other'))).toBeInTheDocument();
  });

  it('says there is no learning state before any judgment was made for the employee', async () => {
    card = cardOf(RECORDS[0].counts, null);
    open();
    const dialog = await openWindow();
    expect(within(dialog).getByText(word('p3.learned.window.noDecision'))).toBeInTheDocument();
  });

  it('says the record could not be read, with nothing to open', async () => {
    card = null;
    const { container } = open();
    expect(await screen.findByText(word('p3.learned.none'))).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: word('p3.learned.open') })).not.toBeInTheDocument();
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
  });
});
