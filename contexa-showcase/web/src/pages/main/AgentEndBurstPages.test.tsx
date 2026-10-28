import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AgentSnapshot, BurstSummary } from '../../api/agentSnapshots';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import AgentBurstPage from './AgentBurstPage';
import AgentEndPage from './AgentEndPage';
import { T5_CONFIRM_APPROVE, T5_CONFIRM_REPORT } from './agentSnapshotFixture';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function burst(label: string, summary: BurstSummary, requests: number): AgentSnapshot {
  const delivered = { outcome: 'DELIVERED', deliveredItems: 0, rule: null };
  return {
    label,
    runId: `run-${label}`,
    caseKey: label.slice(0, 4),
    kind: 'BURST',
    why: '',
    capturedAt: '2026-10-26T12:00:00Z',
    case: null,
    summary,
    run: {
      ...T5_CONFIRM_APPROVE.run,
      steps: Array.from({ length: requests }, (_, i) => ({
        stepNo: i + 1,
        sentBy: 'AGENT_WORK' as const,
        tool: { tool: 'listDocuments', arguments: {} },
        path: '/api/same',
        companyTime: null,
        outcomes: { A: delivered, B: delivered, C1: delivered, C2: delivered, D: delivered },
        decision: null,
      })),
    },
  } as AgentSnapshot;
}

const ON: BurstSummary = {
  requests: 66, delivered: 66, refused: 0, busy: 0, withVerdict: 6, modelCalls: 7, firstStopStep: null,
  deliveredAfterFirstStop: 0,
};
const OFF: BurstSummary = { ...ON, withVerdict: 66, modelCalls: 129 };
const T_ON: BurstSummary = {
  requests: 74, delivered: 2, refused: 72, busy: 17, withVerdict: 4, modelCalls: 4, firstStopStep: 42,
  deliveredAfterFirstStop: 0,
};

let bodies: Record<string, unknown>;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  bodies = {
    '/api/visitor': { predictions: {} },
    '/api/agent-cases/T5': T5_CONFIRM_APPROVE.case,
    '/api/agent-snapshots/T5-confirm-approve': T5_CONFIRM_APPROVE,
    '/api/agent-snapshots/T5-confirm-report': T5_CONFIRM_REPORT,
    '/api/agent-snapshots/M41A-flights-on': burst('M41A-flights-on', ON, 66),
    '/api/agent-snapshots/M41A-flights-off': burst('M41A-flights-off', OFF, 66),
    '/api/agent-snapshots/M41T-flights-on': burst('M41T-flights-on', T_ON, 74),
    '/api/agent-snapshots/M41T-flights-off': burst('M41T-flights-off', { ...T_ON, withVerdict: 72, modelCalls: 69 }, 72),
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body === undefined ? 404 : 200 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open(element: React.ReactElement, path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={element} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('6-5, what the delegating person answer changes (AS-7)', () => {
  it('sets the approve run and the report run side by side, each marked as a stored real run', async () => {
    open(<AgentEndPage />, '/agent/end');

    const approve = within(await screen.findByRole('region', { name: word('main.6-5.column.APPROVE') }));
    const report = within(screen.getByRole('region', { name: word('main.6-5.column.REPORT') }));
    expect(approve.getByText(/실제 실행 · 저장된 기록/)).toBeInTheDocument();
    expect(report.getByText(/실제 실행 · 저장된 기록/)).toBeInTheDocument();
    expect(approve.getByText(word('main.6-5.status.APPROVED'))).toBeInTheDocument();
    expect(approve.getByText(word('main.6-5.say.APPROVE'))).toBeInTheDocument();
    expect(report.getByText(word('main.6-5.say.REPORT'))).toBeInTheDocument();
  });

  it('shows what each answer led to from the stored record: delivered after an approval, refused at sign-in after a report', async () => {
    open(<AgentEndPage />, '/agent/end');

    const approve = within(await screen.findByRole('region', { name: word('main.6-5.column.APPROVE') }));
    const report = within(screen.getByRole('region', { name: word('main.6-5.column.REPORT') }));
    expect(approve.getByText('HTTP 200')).toBeInTheDocument();
    expect(report.getByText('HTTP 401')).toBeInTheDocument();
    // the report run holds no second request: three rows say it was not sent
    expect(report.getAllByText(word('main.6-5.notSent')).length).toBeGreaterThanOrEqual(2);
  });
});

describe('6-5 keeps the conclusions in view (구현계획 AC-N2)', () => {
  it("says what each answer led to in view, and keeps each run's stored record under one line of its own column", async () => {
    const { container } = open(<AgentEndPage />, '/agent/end');
    const approve = await screen.findByRole('region', { name: word('main.6-5.column.APPROVE') });
    const folds = Array.from(container.querySelectorAll('details[data-fold="end-record"]'));
    expect(folds).toHaveLength(2);
    expect(folds.every((fold) => !(fold as HTMLDetailsElement).open)).toBe(true);
    const [approveFold] = folds;
    // the conclusion is outside the fold of its column, the rows and the stored-run mark are inside
    expect(approve).toContainElement(approveFold as HTMLElement);
    expect(approveFold?.contains(screen.getByText(word('main.6-5.say.APPROVE')))).toBe(false);
    // the rest of what the answer means waits in the fold with the records
    expect(approveFold?.contains(screen.getByText(word('main.6-5.more.APPROVE')))).toBe(true);
    expect(approveFold?.textContent).toContain('HTTP 200');
    expect(approveFold?.textContent).toMatch(/실제 실행 · 저장된 기록/);
    // the limit of the two stored runs stays in view
    expect(screen.getByText(word('main.6-5.limit').replace('{{key}}', 'T5'))).toBeInTheDocument();
  });
});

describe('6-6, many requests at once (AS-10, AC-7a)', () => {
  // 구현계획 AC-N2: what each burst shows is said in view; the numbers of the two states and the timeline wait under a line.
  it("says in view what each burst shows and keeps the numbers of the device off and on, and the first burst's timeline, under one line", async () => {
    const { container } = open(<AgentBurstPage />, '/agent/burst');
    const first = await screen.findByRole('region', { name: word('main.6-6.case.M41A') });
    const fold = first.querySelector('details[data-fold="burst-record"]') as HTMLDetailsElement | null;
    expect(fold).not.toBeNull();
    expect(fold?.open).toBe(false);
    expect(fold?.contains(within(first).getByText(word('main.6-6.explain.M41A')))).toBe(false);
    expect(within(first).getAllByRole('table').every((table) => fold?.contains(table))).toBe(true);
    expect(fold?.textContent).toContain(word('main.6-6.timeline'));
    expect(fold?.textContent).toMatch(/실제 실행 · 저장된 기록/);
    expect(container.querySelectorAll('details[data-fold="burst-record"]').length).toBeGreaterThanOrEqual(2);
  });

  it('shows the counts the portal made for each burst, the device off beside the device on', async () => {
    open(<AgentBurstPage />, '/agent/burst');

    const first = within(await screen.findByRole('region', { name: word('main.6-6.case.M41A') }));
    const rows = first.getAllByRole('row').map((row) => row.textContent ?? '');
    expect(rows.find((row) => row.startsWith(word('main.6-6.row.modelCalls')))).toBe(
      `${word('main.6-6.row.modelCalls')}1297`,
    );
    expect(rows.find((row) => row.startsWith(word('main.6-6.row.withVerdict')))).toBe(
      `${word('main.6-6.row.withVerdict')}666`,
    );
    const second = within(screen.getByRole('region', { name: word('main.6-6.case.M41T') }));
    const busy = second.getAllByRole('row').map((row) => row.textContent ?? '').find((row) => row.startsWith(word('main.6-6.row.busy')));
    expect(busy).toContain('17');
    const stop = second.getAllByRole('row').map((row) => row.textContent ?? '').find((row) => row.startsWith(word('main.6-6.row.firstStopStep')));
    expect(stop).toBe(`${word('main.6-6.row.firstStopStep')}4242`);
  });

  /** AC-7a: the counts of 30 and 60 requests are stored measurements, and each block says so with the requests it holds. */
  // 구현계획 AC-N9: the first burst is the view; the other bursts wait under one line, so a phone is not made to scroll past all.
  it('shows the first burst and keeps the other bursts under one line', async () => {
    const { container } = open(<AgentBurstPage />, '/agent/burst');
    const first = await screen.findByRole('region', { name: word('main.6-6.case.M41A') });
    const others = container.querySelector('details[data-fold="burst-others"]') as HTMLDetailsElement | null;
    expect(others).not.toBeNull();
    expect(others?.open).toBe(false);
    expect(others?.contains(first)).toBe(false);
    expect(others?.contains(screen.getByRole('region', { name: word('main.6-6.case.M41T') }))).toBe(true);
  });

  it('marks each burst as a measurement result with the number of requests it holds', async () => {
    open(<AgentBurstPage />, '/agent/burst');

    const first = within(await screen.findByRole('region', { name: word('main.6-6.case.M41A') }));
    expect(first.getByText(word('main.6-6.measured').replace('{{requests}}', '66'))).toBeInTheDocument();
    const second = within(screen.getByRole('region', { name: word('main.6-6.case.M41T') }));
    expect(second.getByText(word('main.6-6.measured').replace('{{requests}}', '74'))).toBeInTheDocument();
  });

  it('leaves out a burst whose stored runs are missing instead of showing an empty one', async () => {
    open(<AgentBurstPage />, '/agent/burst');

    await screen.findByRole('region', { name: word('main.6-6.case.M41A') });
    expect(screen.queryByRole('region', { name: word('main.6-6.case.M41X') })).not.toBeInTheDocument();
  });

  it('folds the first burst requests into one line and opens them on request', async () => {
    open(<AgentBurstPage />, '/agent/burst');

    const first = within(await screen.findByRole('region', { name: word('main.6-6.case.M41A') }));
    await userEvent.click(first.getByText(word('main.6-6.timeline')));
    const toggle = first.getByRole('button', { name: new RegExp(word('main.agent.timeline.expand')) });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(toggle).toHaveTextContent('66');
  });

  it('says the limit: one recorded run for each state', async () => {
    open(<AgentBurstPage />, '/agent/burst');

    expect(await screen.findByText(word('main.6-6.limit'))).toBeInTheDocument();
  });
});
