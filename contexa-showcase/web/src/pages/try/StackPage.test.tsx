import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import StackPage from './StackPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

const FIVE = [{}, {}, {}, {}, {}];

/** A stored request as the screen reads it: Contexa's judgment and the run's learned counts. */
function anatomy(finalAction: string | null, before: number, after: number) {
  return {
    interpretation: { recorded: { finalAction, unresolved: false } },
    recovery: null,
    figures: { baselineBefore: before, baselineAfter: after },
  };
}

/** A stored step result with Contexa's layer as the portal scores it. */
function result(outcome: string, timing: string) {
  return { layers: [{ control: 'D', outcome, verdict: null, evidence: { timing } }] };
}

interface Server {
  journeyRuns: readonly unknown[];
  live: unknown;
  attackRun: string | null;
  anatomies: Record<string, unknown>;
  results: Record<string, unknown>;
  start: { status: number; body: unknown } | null;
}

const server: Server = {
  journeyRuns: [],
  live: null,
  attackRun: 'run-attack',
  anatomies: {},
  results: {},
  start: null,
};

const posts: { url: string; body: string }[] = [];

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(body === null ? null : JSON.stringify(body), { status }));
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  Object.assign(server, {
    journeyRuns: [],
    live: null,
    attackRun: 'run-attack',
    anatomies: {},
    results: {},
    start: null,
  });
  posts.length = 0;
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })),
  );
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      const journey = {
        state: { route: 'DEFAULT', act: 3, step: 'e3-stack', differences: [] },
        runs: server.journeyRuns,
        predictions: [],
      };
      if (init?.method === 'POST') {
        posts.push({ url, body: String(init.body) });
        if (url === '/api/live/runs' && server.start) {
          return json(server.start.body, server.start.status);
        }
        return url === '/api/journey' ? json(journey) : json(null, 404);
      }
      const anatomyOrResult = /^\/api\/runs\/([^/]+)\/steps\/(\d+)\/(anatomy|result)$/.exec(url);
      if (anatomyOrResult) {
        const [, runId, stepNo, kind] = anatomyOrResult;
        const book = kind === 'anatomy' ? server.anatomies : server.results;
        const body = book[`${runId}/${stepNo}`];
        return body === undefined ? json(null, 404) : json(body);
      }
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/journey': journey,
        '/api/live/config': {
          scenarios: [],
          turnstileSiteKey: null,
          dailyRuns: 3,
          remainingToday: 3,
          paused: false,
        },
        '/api/live/runs/current': server.live,
        '/api/cases/A6/measured': server.attackRun
          ? { caseKey: 'A6', middleRun: server.attackRun, list: [] }
          : null,
        '/api/lab/options': {
          employees: [],
          timeSlots: [],
          items: [],
          operations: [],
          cases: [
            { key: 'A6T', requests: FIVE },
            { key: 'A6', requests: FIVE },
          ],
          calls: [],
          assessmentReasons: [],
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

/** The attack as the measurement recorded it: put on hold at the first request, the rest held after it. */
function storeAttack(before: number, after: number, laterTiming = 'STATIC_AUTHORIZATION') {
  server.anatomies['run-attack/1'] = anatomy('ESCALATE', before, after);
  server.results['run-attack/1'] = result('DELIVERED', 'NEXT_REQUEST');
  for (const stepNo of [2, 3, 4, 5]) {
    server.anatomies[`run-attack/${stepNo}`] = anatomy(null, before, after);
    server.results[`run-attack/${stepNo}`] = result('HELD', laterTiming);
  }
}

/** The visitor's completed run of the real work: every request passed. */
function storeWork(before: number, after: number) {
  server.journeyRuns = [{ runId: 'run-work', scenarioKey: 'A6T', status: 'COMPLETED', lab: false }];
  for (const stepNo of [1, 2, 3, 4, 5]) {
    server.anatomies[`run-work/${stepNo}`] = anatomy('ALLOW', before, after);
    server.results[`run-work/${stepNo}`] = result('DELIVERED', 'NEXT_REQUEST');
  }
}

function renderStack() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/try/stack']}>
        <StackPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function lane(kind: 'work' | 'attack'): HTMLElement {
  return screen.getByRole('region', {
    name: `${word(`p3.stack.${kind}.name`)} ${word(`p3.stack.${kind}.what`)}`,
  });
}

/** The lane once the stored records are read (the screen shows the loading state first). */
function laneLoaded(kind: 'work' | 'attack'): Promise<HTMLElement> {
  return screen.findByRole('region', {
    name: `${word(`p3.stack.${kind}.name`)} ${word(`p3.stack.${kind}.what`)}`,
  });
}

function cells(kind: 'work' | 'attack'): readonly string[] {
  return within(lane(kind))
    .getAllByRole('listitem')
    .map((item) => (item.textContent ?? '').trim());
}

function zone(container: HTMLElement, name: string): HTMLElement {
  return required(container.querySelector<HTMLElement>(`[data-zone="${name}"]`), name);
}

/**
 * Screen 3-3 (화면재편 T4): two rows of five cells, the real work the visitor sends and the attack the measurement
 * recorded, with the learned requests each run's record holds; the guide says what is true in each state.
 */
describe('the same lookup sent five times', () => {
  it('before sending, shows the earlier attack record, five empty cells and Send as the main button', async () => {
    storeAttack(24, 24);
    const { container } = renderStack();

    await waitFor(() => expect(cells('attack')[0]).toContain(word('verdict.review')));
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.3-3.title'));
    expect(zone(container, 'title')).toHaveTextContent(word('p3.stack.guide.unsent'));
    expect(cells('attack').slice(1)).toEqual([2, 3, 4, 5].map((n) => `${n} ${word('p3.stack.cell.HELD')}`));
    expect(
      within(lane('attack')).getByText(fill('p3.stack.learned.same', { from: '24' })),
    ).toBeInTheDocument();

    expect(cells('work')).toHaveLength(5);
    expect(cells('work').every((text) => text.endsWith(word('p3.stack.cell.unsent')))).toBe(true);
    // V-38: "not sent yet" shows in the work row (faded), and the attack row says it is an earlier real send.
    for (const unsent of within(lane('work')).getAllByText(word('p3.stack.cell.unsent'))) {
      expect(unsent.closest('.visually-hidden')).toBeNull();
    }
    expect(within(lane('attack')).getByText(word('p3.stack.attack.earlier'))).toBeInTheDocument();
    expect(within(lane('work')).queryByText(word('p3.stack.attack.earlier'))).not.toBeInTheDocument();
    // No learned line before the visitor's run exists.
    expect(lane('work').querySelector('p')).toBeNull();
    // P-32: every run starts from the same learned state, named with its count from the record.
    expect(screen.getByText(fill('p3.stack.reset', { n: '24' }))).toBeInTheDocument();

    const send = await screen.findByRole('button', { name: word('p3.stack.send') });
    expect(send).toHaveAttribute('data-main');
    await waitFor(() => expect(send).toBeEnabled());
    expect(screen.queryByRole('link', { name: word('frame.nextNamed').replace('{{name}}', word('more.name.learn-after')) })).not.toBeInTheDocument();

    // Only the attack row has numbers, an earlier real request of the same situation; its details are one chip.
    expect(zone(container, 'source')).toHaveTextContent(word('frame.source.earlier'));
    expect(within(zone(container, 'source')).queryAllByRole('button')).toHaveLength(0);
    expect(within(zone(container, 'body')).getAllByRole('button')).toHaveLength(1);
    expect(screen.getByRole('button', { name: word('frame.detail') })).toBeInTheDocument();
  });

  it('names a request stopped by an earlier judgment as such', async () => {
    storeAttack(24, 24, 'PRIOR_DECISION');
    renderStack();
    await waitFor(() => expect(cells('attack')[1]).toContain(word('p3.stack.cell.prior')));
  });

  it('while the run goes, fills the cells from the live answers and shows no main button', async () => {
    storeAttack(24, 24);
    server.live = {
      liveRunId: 'live-1',
      scenario: 'A6T',
      status: 'RUNNING',
      queuePosition: 0,
      queueWaitSeconds: null,
      runId: 'run-live',
      readyMs: null,
      steps: [
        {
          stepNo: 1,
          operation: 'lookup',
          layers: { D: { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 1, elapsedMs: 30 } },
        },
        {
          stepNo: 2,
          operation: 'lookup',
          layers: { D: { outcome: 'STOPPED', httpStatus: 403, deliveredItems: 0, elapsedMs: 20 } },
        },
      ],
      challenge: null,
      failure: null,
    };
    const { container } = renderStack();

    await waitFor(() => expect(cells('work')[0]).toContain(word('p3.stack.cell.DELIVERED')));
    expect(cells('work')[1]).toContain(word('p3.stack.cell.STOPPED'));
    expect(
      cells('work')
        .slice(2)
        .every((text) => text.endsWith(word('p3.stack.cell.waiting'))),
    ).toBe(true);
    expect(zone(container, 'title')).toHaveTextContent(word('p3.stack.guide.running'));
    expect(within(zone(container, 'actions')).queryByRole('button')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: word('frame.nextNamed').replace('{{name}}', word('more.name.learn-after')) })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: word('frame.detail') })).not.toBeInTheDocument();
  });

  it.each([
    { work: [24, 29], attack: [24, 24], shown: { from: '24', to: '29', attack: '24' } },
    { work: [1200, 1205], attack: [1200, 1200], shown: { from: '1,200', to: '1,205', attack: '1,200' } },
  ])(
    'once stored, shows each judgment and the learned requests of the records ($shown.to)',
    async (record) => {
      storeAttack(record.attack[0] ?? 0, record.attack[1] ?? 0);
      storeWork(record.work[0] ?? 0, record.work[1] ?? 0);
      const { container } = renderStack();

      expect(
        await within(await laneLoaded('work')).findByText(
          fill('p3.stack.learned.changed', { from: record.shown.from, to: record.shown.to }),
        ),
      ).toBeInTheDocument();
      expect(cells('work').every((text) => text.endsWith(word('verdict.allow')))).toBe(true);
      expect(
        within(lane('attack')).getByText(fill('p3.stack.learned.same', { from: record.shown.attack })),
      ).toBeInTheDocument();
      expect(zone(container, 'title')).toHaveTextContent(word('screen.3-3.guide'));
      expect(screen.getByRole('link', { name: word('frame.nextNamed').replace('{{name}}', word('more.name.learn-after')) })).toHaveAttribute(
        'href',
        '/try/summary/learning',
      );
      expect(screen.queryByRole('button', { name: word('p3.stack.send') })).not.toBeInTheDocument();
      expect(zone(container, 'source')).toHaveTextContent(word('p3.stack.source.both'));
      expect(screen.getByRole('button', { name: word('frame.detail') })).toBeInTheDocument();
      // The difference this screen shows is marked as seen on the server.
      await waitFor(() =>
        expect(
          posts.some((post) => post.url === '/api/journey' && post.body.includes('"difference":6')),
        ).toBe(true),
      );

      // The meter's details are left to the decision details; the old notes are gone.
      const text = document.body.textContent ?? '';
      for (const key of [
        'meter.observations',
        'meter.deltas',
        'stack.notice',
        'stack.live',
        'stack.replay',
      ]) {
        // Old keys may be removed from the dictionaries later (R9); a removed key is gone from the screen too.
        const old = KO[key];
        if (old !== undefined) {
          expect(text, key).not.toContain(old);
        }
      }
    },
  );

  it('says a send that did not finish and offers Send again', async () => {
    storeAttack(24, 24);
    server.live = {
      liveRunId: 'live-1',
      scenario: 'A6T',
      status: 'FAILED',
      queuePosition: 0,
      queueWaitSeconds: null,
      runId: null,
      readyMs: null,
      steps: [],
      challenge: null,
      failure: 'TIMEOUT',
    };
    const { container } = renderStack();
    await waitFor(() => expect(zone(container, 'title')).toHaveTextContent(word('p3.stack.guide.failed')));
    expect(await screen.findByRole('button', { name: word('p3.stack.send') })).toBeInTheDocument();
  });

  it("says when today's sends are used up and leads on with the earlier record", async () => {
    storeAttack(24, 24);
    server.start = { status: 429, body: { reason: 'DAILY_LIMIT' } };
    const { container } = renderStack();
    const send = await screen.findByRole('button', { name: word('p3.stack.send') });
    await waitFor(() => expect(send).toBeEnabled());
    fireEvent.click(send);

    await waitFor(() => expect(zone(container, 'title')).toHaveTextContent(word('p3.stack.guide.closed')));
    expect(screen.getByText(word('state.dailyLimit'))).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('frame.nextNamed').replace('{{name}}', word('more.name.learn-after')) })).toHaveAttribute(
      'href',
      '/try/summary/learning',
    );
    expect(screen.queryByRole('button', { name: word('p3.stack.send') })).not.toBeInTheDocument();
  });

  it('says when the attack has no earlier record', async () => {
    server.attackRun = null;
    renderStack();
    expect(await within(await laneLoaded('attack')).findByText(word('p3.stack.attack.none'))).toBeInTheDocument();
    expect(screen.queryByText(word('p3.stack.attack.earlier'))).not.toBeInTheDocument();
    // Without a record the start state is said without its count.
    expect(screen.getByText(word('p3.stack.resetPlain'))).toBeInTheDocument();
  });
});
