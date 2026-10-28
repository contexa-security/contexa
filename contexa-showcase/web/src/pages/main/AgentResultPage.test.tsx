import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import AgentResultPage from './AgentResultPage';
import snapshot from './agentSnapshotFixture';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

let bodies: Record<string, unknown>;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  bodies = {
    '/api/visitor': { predictions: {} },
    '/api/journey': { state: { route: 'DEFAULT', act: 6, step: 'agent-result', differences: [] }, runs: [], predictions: [] },
    '/api/live/runs/current': null,
    '/api/agent-cases/T5': snapshot.case,
    '/api/agent-snapshots/T5-confirm-approve': snapshot,
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = bodies[url];
      return new Response(body === undefined || body === null ? null : JSON.stringify(body), {
        status: body === undefined || body === null ? 404 : 200,
      });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/agent/result']}>
        <Routes>
          <Route path="*" element={<AgentResultPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('6-7, the agent result on one page (AS-8)', () => {
  it('shows a stored real run when the visitor has none, and says so', async () => {
    open();

    expect(await screen.findByText(/실제 실행 · 저장된 기록/)).toBeInTheDocument();
  });

  it('puts the sent requests, the first stop and what went to the delegating person on one line, from the scoring', async () => {
    open();

    const summary = await screen.findByRole('region', { name: word('main.6-7.summary') });
    // T5: one request sent, control D first stopped at request 1, the delegating person was asked
    expect(within(summary).getByText(word('main.6-7.sent'))).toBeInTheDocument();
    expect(within(summary).getByText(word('main.6-7.firstStop'))).toBeInTheDocument();
    expect(within(summary).getByText(word('main.6-7.toPerson'))).toBeInTheDocument();
    expect(within(summary).getAllByText('1').length).toBeGreaterThanOrEqual(2);
  });

  it('lists the five approaches as lanes with what each let out and where each first stopped', async () => {
    open();

    const lanes = await screen.findByRole('region', { name: word('main.6-7.lanes') });
    for (const name of ['방화벽', '로그인 인증', '고정 규칙', '승인 기록 규칙', 'Contexa']) {
      expect(within(lanes).getByText(name)).toBeInTheDocument();
    }
    // control D stopped the work at request 1; the other four never did
    expect(within(lanes).getAllByText(word('main.6-7.neverStopped'))).toHaveLength(4);
    expect(within(lanes).getByText(new RegExp(word('main.6-7.stoppedAt').replace('{{step}}', '1')))).toBeInTheDocument();
  });

  it('says the limit of one run of a model and of one case', async () => {
    open();

    expect(await screen.findByText(word('main.agent.measure.limit'))).toBeInTheDocument();
  });
});

/**
 * AS-8: "what went to the delegating person" is the same on every screen: control D asked the person when its rule says
 * so, or the run holds a confirmation record. A run stored before confirmations were recorded (an old recording) has D's
 * rule and no record, and must still say the person was asked, as the console (6-2) does.
 */
describe('6-7, what went to the delegating person (AS-8)', () => {
  function summaryValue(name: string): HTMLElement {
    const summary = screen.getByRole('region', { name: word('main.6-7.summary') });
    const term = within(summary).getByText(word(name));
    return required(term.parentElement?.querySelector<HTMLElement>('dd'), 'value of ' + name);
  }

  it('says the person was asked when the run holds the confirmation', async () => {
    open();

    await screen.findByRole('region', { name: word('main.6-7.summary') });
    expect(summaryValue('main.6-7.toPerson')).toHaveTextContent(word('main.6-7.toPersonYes'));
  });

  it("says the person was asked when only control D's rule says so (a run stored before records)", async () => {
    const legacy = {
      ...snapshot,
      run: { ...snapshot.run, confirmation: null },
    };
    bodies['/api/agent-snapshots/T5-confirm-approve'] = legacy;
    open();

    await screen.findByRole('region', { name: word('main.6-7.summary') });
    expect(summaryValue('main.6-7.toPerson')).toHaveTextContent(word('main.6-7.toPersonYes'));
  });

  it('says nobody was asked when neither the rule nor a record says so', async () => {
    const quiet = {
      ...snapshot,
      run: {
        ...snapshot.run,
        confirmation: null,
        steps: snapshot.run.steps.map((step) => ({
          ...step,
          outcomes: { ...step.outcomes, D: { ...step.outcomes['D'], rule: null } },
        })),
      },
    };
    bodies['/api/agent-snapshots/T5-confirm-approve'] = quiet;
    open();

    await screen.findByRole('region', { name: word('main.6-7.summary') });
    expect(summaryValue('main.6-7.toPerson')).toHaveTextContent(word('main.6-7.toPersonNo'));
  });
});
