import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import FollowPage from './FollowPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

const FORCED_REASON = 'Development-only forced decision (showcase.dev.forced-actions)';

/** A stored release as the anatomy carries it: every step done, the original request sent again. */
function release(reasoning: string, delivered: number) {
  return {
    released: true,
    reason: null,
    blocked_at: '2026-10-19T07:20:44Z',
    code_requested_at: '2026-10-19T07:20:44Z',
    verified_at: '2026-10-19T07:20:46Z',
    requested_at: '2026-10-19T07:20:48Z',
    approved_at: '2026-10-19T07:20:50Z',
    reissue_sent_at: '2026-10-19T07:20:54Z',
    reissue_status: 200,
    reissue_outcome: 'DELIVERED',
    reissue_delivered: delivered,
    block_record: { status: 'UNBLOCK_REQUESTED', reasoning, mfaVerified: true, unblockReason: 'GB-500 이관' },
  };
}

interface Server {
  stats: unknown;
  actions: unknown;
  latest: unknown;
  anatomy: unknown;
}

const server: Server = { stats: null, actions: null, latest: null, anatomy: null };

/** The public statistics as the portal returns them; the header reads the run counts. */
function stats(engineActions: Readonly<Record<string, number>>, blockedAfterReview: number) {
  return {
    runs: { completed: 0, failed: 0, today: 0, live: 0, firstAt: null, lastAt: null },
    engineActions,
    blockedAfterReview,
  };
}

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(body === null ? null : JSON.stringify(body), { status }));
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  Object.assign(server, { stats: null, actions: null, latest: null, anatomy: null });
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
          state: { route: 'DEFAULT', act: 2, step: 'follow', differences: [] },
          runs: [],
          predictions: [],
        },
        '/api/stats': server.stats,
        '/api/engine/actions': server.actions,
        '/api/follow/release': server.latest,
        '/api/runs/run-release/steps/1/anatomy': server.anatomy,
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

function open() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/try/follow']}>
        <FollowPage ending={false} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The row of one judgment, by its chip's data. */
function row(container: HTMLElement, verdict: string): HTMLElement {
  return required(container.querySelector<HTMLElement>(`[data-verdict="${verdict}"]`), verdict);
}

/** Two records with different values, so a row that shows a constant fails one of them. */
const RECORDS = [
  {
    name: 'the core defaults',
    ttl: { ALLOW: 15, CHALLENGE: 1800, ESCALATE: 300 },
    counts: { ALLOW: 4598, CHALLENGE: 1908, ESCALATE: 1136, BLOCK: 23 },
    promoted: 86,
    shown: {
      ALLOW: fill('p2.follow.time.seconds', { n: '15' }),
      CHALLENGE: fill('p2.follow.time.minutes', { n: '30' }),
      ESCALATE: fill('p2.follow.time.minutes', { n: '5' }),
      counts: { ALLOW: '4,598', CHALLENGE: '1,908', ESCALATE: '1,136', BLOCK: '23' },
      promoted: '86',
    },
  },
  {
    name: 'another setting',
    ttl: { ALLOW: 45, CHALLENGE: 600, ESCALATE: 120 },
    counts: { ALLOW: 12, CHALLENGE: 7, ESCALATE: 3, BLOCK: 1 },
    promoted: 2,
    shown: {
      ALLOW: fill('p2.follow.time.seconds', { n: '45' }),
      CHALLENGE: fill('p2.follow.time.minutes', { n: '10' }),
      ESCALATE: fill('p2.follow.time.minutes', { n: '2' }),
      counts: { ALLOW: '12', CHALLENGE: '7', ESCALATE: '3', BLOCK: '1' },
      promoted: '2',
    },
  },
] as const;

/** Screen 2-6, what follows each judgment (화면재편 T7), with the latest real release under the four rows. */
describe('what follows each judgment', () => {
  it.each(RECORDS)('says what each hold does and names every count by its judgment ($name)', async (record) => {
    server.actions = {
      ALLOW: { httpStatus: 200, ttlSeconds: record.ttl.ALLOW },
      CHALLENGE: { httpStatus: 401, ttlSeconds: record.ttl.CHALLENGE },
      ESCALATE: { httpStatus: 423, ttlSeconds: record.ttl.ESCALATE },
      BLOCK: { httpStatus: 403, ttlSeconds: null },
    };
    server.stats = stats(record.counts, record.promoted);
    const { container } = open();
    await screen.findByText(fill('p2.follow.count.ALLOW', { n: record.shown.counts.ALLOW }));

    // V-50: what the hold does, not "kept for n"; the review's hold and its block after the same time agree.
    expect(row(container, 'ALLOW')).toHaveTextContent(fill('p2.follow.hold.ALLOW', { time: record.shown.ALLOW }));
    expect(row(container, 'CHALLENGE')).toHaveTextContent(
      fill('p2.follow.hold.CHALLENGE', { time: record.shown.CHALLENGE }),
    );
    expect(row(container, 'ESCALATE')).toHaveTextContent(
      fill('p2.follow.hold.ESCALATE', { time: record.shown.ESCALATE }),
    );
    expect(row(container, 'ESCALATE')).toHaveTextContent(
      fill('p2.follow.next.ESCALATE', { time: record.shown.ESCALATE }),
    );
    expect(row(container, 'BLOCK')).toHaveTextContent(word('p2.follow.hold.none'));

    // V-16: each count is named by its judgment; V-15: the block row sets its two counts side by side.
    for (const verdict of ['ALLOW', 'CHALLENGE', 'ESCALATE'] as const) {
      expect(row(container, verdict)).toHaveTextContent(
        fill(`p2.follow.count.${verdict}`, { n: record.shown.counts[verdict] }),
      );
    }
    expect(row(container, 'BLOCK')).toHaveTextContent(
      fill('p2.follow.blockCount', { n: record.shown.counts.BLOCK, promoted: record.shown.promoted }),
    );
    const text = container.textContent ?? '';
    expect(text).not.toContain('지금까지');
    expect(text).not.toContain('동안 유지');
    // V-51: the code goes to the account's owner, the deck's words.
    expect(row(container, 'CHALLENGE')).toHaveTextContent(word('p2.follow.next.CHALLENGE'));
    expect(word('p2.follow.next.CHALLENGE')).toContain('계정 주인');
    expect(word('p2.follow.next.CHALLENGE')).not.toContain('정상 사용자');
  });

  it('names a forced block in plain words, folds the raw setting name and says why the original request was not learned', async () => {
    server.actions = { BLOCK: { httpStatus: 403, ttlSeconds: null } };
    server.stats = stats({ BLOCK: 1 }, 0);
    server.latest = { runId: 'run-release', stepNo: 1, scenarioKey: 'A3T', forcedAction: 'BLOCK', approvedAt: null };
    server.anatomy = {
      recovery: { challenge: null, release: release(FORCED_REASON, 4831) },
      learning: {
        template: { baselineUpdateCount: 24 },
        atRunEnd: { baselineUpdateCount: 24 },
        newBehaviourDocuments: [
          { action: 'ALLOW', requestPath: null, timestamp: null, content: 'User accessed Admin approved unblock' },
        ],
      },
    };
    const { container } = open();
    const record = await screen.findByRole('region', { name: word('follow.release.title') });

    // V-49: the body says what happened; the setting's name is only in the folded original.
    expect(within(record).getByText(word('follow.release.forcedReason'))).toBeVisible();
    const original = required(record.querySelector('details'), 'the folded original');
    expect(original).not.toHaveAttribute('open');
    expect(within(original).getByText(word('follow.release.raw'))).toBeInTheDocument();
    expect(within(original).getByText(FORCED_REASON)).not.toBeVisible();

    // B-16: the chip holds the count and the status only; its label is the row's name.
    expect(within(record).getByText(fill('follow.release.resentValue', { items: '4,831', status: '200' }))).toBeInTheDocument();
    expect(record.textContent ?? '').not.toContain(fill('main.release.done', { items: '4,831', status: '200' }));

    // V-14: the forced block kept no facts of the original request, so the release did not learn it.
    expect(within(record).getByText(word('follow.release.learnForced'))).toBeInTheDocument();
    expect(container.textContent ?? '').not.toContain('개발용 설정');
  });

  it("shows the engine's own reason as written and no forced note for a block the engine made", async () => {
    server.actions = { BLOCK: { httpStatus: 403, ttlSeconds: null } };
    server.stats = stats({ BLOCK: 1 }, 0);
    server.latest = { runId: 'run-release', stepNo: 1, scenarioKey: 'A3', forcedAction: null, approvedAt: null };
    server.anatomy = {
      recovery: { challenge: null, release: release('Bulk export of an unassigned project at night', 1) },
      learning: { template: { baselineUpdateCount: 24 }, atRunEnd: { baselineUpdateCount: 25 }, newBehaviourDocuments: [] },
    };
    open();
    const record = await screen.findByRole('region', { name: word('follow.release.title') });
    expect(within(record).getByText('Bulk export of an unassigned project at night')).toBeVisible();
    expect(record.querySelector('details')).toBeNull();
    expect(within(record).queryByText(word('follow.release.forcedReason'))).not.toBeInTheDocument();
    expect(within(record).queryByText(word('follow.release.learnForced'))).not.toBeInTheDocument();
    expect(within(record).getByText(fill('follow.release.resentValue', { items: '1', status: '200' }))).toBeInTheDocument();
  });
});
