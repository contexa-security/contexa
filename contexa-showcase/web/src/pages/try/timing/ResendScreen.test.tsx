import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { required } from '../../../test/required';
import { analysisRecord, contexaResult, measuredCase, portalStub } from '../../../test/timingFixture';
import ResendScreen from './ResendScreen';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

// The live send through the visitor's gate, set per test; the screen only reads its state and calls send.
const sender = vi.hoisted(() => ({
  send: (() => Promise.resolve()) as () => Promise<void>,
  sending: false,
  ready: true,
  refusal: null as string | null,
  waiting: false,
  turnstileContainer: () => undefined,
  turnstileRequired: false,
}));
vi.mock('../../../hooks/useLiveSend', () => ({ useLiveSend: () => sender }));

const OWN_SYNC = 'run-0a3000000001';
const OWN_ASYNC = 'run-0a3a00000001';
const MEASURED_SYNC = 'run-0a30000000m1';

function line(runId: string, scenarioKey: string, status = 'COMPLETED') {
  return {
    runId,
    scenarioKey,
    classification: 'THREAT',
    status,
    lab: false,
    business: {},
    engineAction: null,
    exposedItems: 0,
    correct: null,
  };
}

/** The records of a sent request: its first step, its analysis time and, for the attack sent twice, its second step. */
function records(
  runId: string,
  first: Parameters<typeof contexaResult>[0],
  analysisMs: number,
  next?: Parameters<typeof contexaResult>[0],
) {
  return {
    [`/api/runs/${runId}/steps/1/result`]: contexaResult(first),
    [`/api/runs/${runId}/steps/1/anatomy`]: analysisRecord(analysisMs),
    ...(next ? { [`/api/runs/${runId}/steps/2/result`]: contexaResult(next) } : {}),
  };
}

const SYNC_RECORDS = records(
  OWN_SYNC,
  { outcome: 'HELD', verdict: 'ESCALATE', timing: 'BEFORE_RESPONSE', deliveredItems: 0, responseMs: 5922 },
  5810,
);
const ASYNC_RECORDS = records(
  OWN_ASYNC,
  { outcome: 'DELIVERED', verdict: 'ESCALATE', timing: 'NEXT_REQUEST', deliveredItems: 4831, responseMs: 57 },
  4199,
  { outcome: 'HELD', verdict: null, timing: 'PRIOR_DECISION', deliveredItems: 0, responseMs: 40 },
);
const MEASURED_RECORDS = records(
  MEASURED_SYNC,
  { outcome: 'HELD', verdict: 'BLOCK', timing: 'BEFORE_RESPONSE', deliveredItems: 0, responseMs: 3510 },
  3447,
);
const MEASURED = measuredCase('A3', { results: { STOPPED: 5 }, middleRun: MEASURED_SYNC });

// The two cases' definitions: the request sent before the response has one step, the one from the next request two.
const OPTIONS = {
  employees: [{ key: 'adm-a', displayName: 'Administrator A' }],
  cases: [
    { key: 'A3', steps: 1, conditions: { employee: 'adm-a' }, requests: [{ items: 4831 }] },
    { key: 'A3A', steps: 2, conditions: { employee: 'adm-a' }, requests: [{ items: 4831 }, { items: 4831 }] },
  ],
};

let bodies: Record<string, unknown> = {};

function journeyWith(...runs: ReturnType<typeof line>[]) {
  return { state: { route: 'DEFAULT', act: 4, step: 'sync-try', differences: [] }, runs, predictions: [] };
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  bodies = { '/api/cases/A3/measured': MEASURED, '/api/lab/options': OPTIONS, ...MEASURED_RECORDS };
  Object.assign(sender, {
    send: vi.fn(() => Promise.resolve()),
    sending: false,
    ready: true,
    refusal: null,
    waiting: false,
  });
  vi.stubGlobal('fetch', vi.fn(portalStub(() => bodies)));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/try/timing/try']}>
        <ResendScreen />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function card(mode: 'sync' | 'async') {
  return screen.getByRole('region', { name: word(`p4.mode.${mode}`) });
}

/** Screen 4-1 (화면재편 T4): Send, then the two requests side by side, each as its stored record says. */
describe('sending it the other way', () => {
  it('shows the request sent before next to the one not sent yet, with Send as the one main button', async () => {
    bodies = { ...bodies, '/api/journey': journeyWith(line(OWN_SYNC, 'A3')), ...SYNC_RECORDS };
    const { container } = open();
    const sync = card('sync');
    expect(await within(sync).findByText(fill('p4.items', { items: '0' }))).toBeInTheDocument();
    expect(within(sync).getByText(word('p4.try.own'))).toBeInTheDocument();
    expect(within(sync).getByText(fill('p4.response', { seconds: '5.9' }))).toBeInTheDocument();
    expect(
      within(sync).getByText(
        fill('p4.judged', { seconds: '5.8', applied: word('p4.applied.BEFORE_RESPONSE') }),
      ),
    ).toBeInTheDocument();
    expect(within(sync).getByText(word('verdict.review'))).toBeInTheDocument();
    const async = card('async');
    expect(within(async).getByText(word('p4.try.notSent'))).toBeInTheDocument();
    // L-11: the card not sent yet shows, faintly, the lines its result will fill, with no value in them; they are
    // drawing only, so a screen reader hears "not sent yet" alone.
    const ghost = required(async.querySelector<HTMLElement>('[data-ghost]'), 'the faint lines');
    expect(ghost).toHaveAttribute('aria-hidden', 'true');
    expect(Array.from(ghost.children, (child) => child.textContent)).toEqual([
      fill('p4.items', { items: '—' }),
      fill('p4.response', { seconds: '—' }),
      fill('p4.judged', { seconds: '—', applied: '—' }),
    ]);
    expect(sync.querySelector('[data-ghost]')).toBeNull();

    // Send is the one main button until there is a result (R-2, as on 1-2 and 3-3); then the main button names 4-2.
    const send = required(
      container.querySelector<HTMLElement>('[data-zone="actions"] [data-main]'),
      'the main button',
    );
    expect(send).toHaveTextContent(word('p1.predict.send'));
    expect(within(async).queryByRole('button', { name: word('p1.predict.send') })).not.toBeInTheDocument();
    fireEvent.click(send);
    expect(sender.send).toHaveBeenCalledTimes(1);
    expect(
      screen.queryByRole('link', {
        name: word('frame.nextNamed').replace('{{name}}', word('more.name.sync-compare')),
      }),
    ).not.toBeInTheDocument();
    const source = required(container.querySelector<HTMLElement>('[data-zone="source"]'), 'the source line');
    expect(source).toHaveTextContent(word('frame.source.run'));
  });

  it("shows both of the visitor's requests once the new one ended, and leads on to the result", async () => {
    bodies = {
      ...bodies,
      '/api/journey': journeyWith(line(OWN_SYNC, 'A3'), line(OWN_ASYNC, 'A3A')),
      ...SYNC_RECORDS,
      ...ASYNC_RECORDS,
    };
    const { container } = open();
    const async = card('async');
    expect(await within(async).findByText(fill('p4.items', { items: '4,831' }))).toBeInTheDocument();
    expect(within(async).getByText(word('p4.try.now'))).toBeInTheDocument();
    expect(within(async).getByText(fill('p4.response', { seconds: '0.06' }))).toBeInTheDocument();
    expect(
      within(async).getByText(
        fill('p4.judged', { seconds: '4.2', applied: word('p4.applied.NEXT_REQUEST') }),
      ),
    ).toBeInTheDocument();
    expect(await within(async).findByText(word('p4.try.next.stopped'))).toBeInTheDocument();
    expect(container.querySelector('[data-ghost]')).toBeNull();
    // The request sent before the response has one request only: no next-request line.
    expect(within(card('sync')).queryByText(word('p4.try.next.stopped'))).not.toBeInTheDocument();
    expect(
      screen.getByRole('link', {
        name: word('frame.nextNamed').replace('{{name}}', word('more.name.sync-compare')),
      }),
    ).toHaveAttribute('href', '/try/timing/compare');
    expect(screen.queryByRole('button', { name: word('p1.predict.send') })).not.toBeInTheDocument();
    const source = required(container.querySelector<HTMLElement>('[data-zone="source"]'), 'the source line');
    expect(source).toHaveTextContent(word('frame.source.run'));
    expect(within(source).getAllByRole('button')).toHaveLength(1);
  });

  it('names the earlier real request when the visitor skipped part 1, before and after sending', async () => {
    const { container, unmount } = open();
    const sync = card('sync');
    expect(await within(sync).findByText(word('p4.try.record'))).toBeInTheDocument();
    expect(await within(sync).findByText(fill('p4.response', { seconds: '3.5' }))).toBeInTheDocument();
    expect(within(sync).getByText(word('verdict.block'))).toBeInTheDocument();
    expect(required(container.querySelector('[data-zone="source"]'), 'the source line')).toHaveTextContent(
      word('frame.source.earlier'),
    );
    unmount();

    bodies = { ...bodies, '/api/journey': journeyWith(line(OWN_ASYNC, 'A3A')), ...ASYNC_RECORDS };
    const after = open();
    expect(await within(card('async')).findByText(fill('p4.items', { items: '4,831' }))).toBeInTheDocument();
    expect(
      required(after.container.querySelector('[data-zone="source"]'), 'the source line'),
    ).toHaveTextContent(word('p4.try.source.mixed'));
  });

  it('points to the request still being sent instead of sending another', async () => {
    bodies = {
      ...bodies,
      '/api/journey': journeyWith(line(OWN_SYNC, 'A3')),
      '/api/live/runs/current': {
        liveRunId: 'live-1',
        scenario: 'A3A',
        status: 'RUNNING',
        queuePosition: 0,
        queueWaitSeconds: null,
        runId: OWN_ASYNC,
        readyMs: null,
        steps: [],
        challenge: null,
        failure: null,
      },
      ...SYNC_RECORDS,
    };
    const { container } = open();
    const async = card('async');
    expect(await within(async).findByText(word('p4.try.going'))).toBeInTheDocument();
    expect(async.querySelector('[data-ghost]')).not.toBeNull();
    const watch = required(
      container.querySelector<HTMLElement>('[data-zone="actions"] [data-main]'),
      'the main button',
    );
    expect(watch).toHaveTextContent(word('p4.try.watch'));
    expect(watch).toHaveAttribute('href', '/try/attacker/run?mode=async&from=timing');
    expect(screen.queryByRole('button', { name: word('p1.predict.send') })).not.toBeInTheDocument();
  });

  it('draws no send-again chip, code notation or run number: one source button in the body zones at most', async () => {
    bodies = {
      ...bodies,
      '/api/journey': journeyWith(line(OWN_SYNC, 'A3'), line(OWN_ASYNC, 'A3A')),
      ...SYNC_RECORDS,
      ...ASYNC_RECORDS,
    };
    const { container } = open();
    await within(card('async')).findByText(fill('p4.items', { items: '4,831' }));
    const zones = Array.from(
      container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'),
    );
    const pressables = zones.flatMap((zone) => Array.from(zone.querySelectorAll('button, a[href]')));
    expect(pressables).toHaveLength(1);
    expect(pressables[0]).toHaveTextContent(word('frame.source.open'));
    const text = document.body.textContent ?? '';
    expect(text).not.toContain(word('timing.try.again'));
    expect(text).not.toContain('@Protectable');
    expect(text).not.toMatch(/run-[0-9a-f]{6,}/);
  });
});
