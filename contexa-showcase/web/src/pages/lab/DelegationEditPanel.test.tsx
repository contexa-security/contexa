import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import snapshot from '../main/agentSnapshotFixture';
import { DelegationEditPanel } from './DelegationEditPanel';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

/** The accessible name of a quantity choice: its words exactly, so 40 is not mistaken for 400. */
function quantityName(n: number): string {
  return word('labAgent.edit.quantityValue').replace('{{n}}', String(n));
}

/**
 * docs/agent Agent중심-화면 AS-12: the lab lets a visitor change the values of the delegation of one case (the quantity limit, the
 * period, the allowed operations, each from the portal's fixed lists), choose the path, and read the stored result of
 * that combination first (no model is called); a real run of the same choice goes through the portal's gate.
 */
const EDIT = {
  case: 'ED1',
  title: { ko: '위임장의 값 하나를 바꾼 문서 내보내기', en: 'An export after one value was changed' },
  quantities: [40, 100, 400],
  periods: ['VALID', 'EXPIRED', 'REVOKED'],
  operations: ['READ_ONLY', 'READ_EXPORT'],
};

const BASE = required(snapshot.case, 'the frozen run carries its case');

const CASE = {
  ...BASE,
  key: 'ED1',
  title: EDIT.title,
  instruction: { ko: 'HX-310 문서 400건을 내보내 줘.', en: 'Export 400 documents of HX-310.' },
  delegation: {
    ...BASE.delegation,
    summary: { ko: 'HX-310 설계 검토 자료 내보내기(요청마다 40건까지)', en: 'Export, up to 40 a request' },
    operations: ['PROJECT_LIST', 'DOCUMENT_LIST', 'DOCUMENT_READ', 'EXPORT'],
    validFromMinutes: -60,
    validUntilMinutes: 180,
    status: 'ACTIVE',
    maxItemsPerRequest: 40,
  },
};

function stored(url: string, ranAt = '2026-10-27T07:00:00Z') {
  return { caseKey: 'ED1', path: 'OAUTH2_DELEGATED', choice: null, ranAt, stale: false, caseView: CASE, run: snapshot.run, url };
}

const NOW = Date.parse('2026-10-27T12:00:00Z');
let bodies: Record<string, unknown>;
let fetched: string[];

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  fetched = [];
  bodies = {
    '/api/visitor': { predictions: {} },
    '/api/live/config': {
      scenarios: [],
      agentCases: [],
      delegationEdit: EDIT,
      liveTicketsLeft: 7,
      turnstileSiteKey: null,
      dailyRuns: 10,
      remainingToday: 10,
      paused: false,
    },
    '/api/agent-cases/ED1': CASE,
    '/api/agent-menu': { cases: [], paths: ['OAUTH2_DELEGATED', 'OAUTH2_AGENT', 'SESSION'], items: [], delegationEdit: EDIT },
    '/api/agent-menu/ED1/OAUTH2_DELEGATED?quantity=40&period=VALID&operations=READ_EXPORT': stored('default'),
    '/api/agent-menu/ED1/OAUTH2_DELEGATED?quantity=400&period=VALID&operations=READ_EXPORT': stored('q400'),
    '/api/agent-menu/ED1/SESSION?quantity=400&period=EXPIRED&operations=READ_ONLY': stored('session'),
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      fetched.push(url);
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body === undefined ? 404 : 200 });
    }),
  );
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <DelegationEditPanel />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('the delegation edit in the lab (AS-12)', () => {
  it('shows the work asked and the three values to change, each at the case\'s own value', async () => {
    open();

    const panel = await screen.findByRole('region', { name: word('labAgent.edit.title') });
    expect(await within(panel).findByText('HX-310 문서 400건을 내보내 줘.')).toBeInTheDocument();
    const quantity = within(panel).getByRole('radiogroup', { name: word('labAgent.edit.quantity') });
    const period = within(panel).getByRole('radiogroup', { name: word('labAgent.edit.period') });
    const operations = within(panel).getByRole('radiogroup', { name: word('labAgent.edit.operations') });
    expect(within(quantity).getAllByRole('radio').map((radio) => (radio as HTMLInputElement).value)).toEqual(['40', '100', '400']);
    expect(within(period).getAllByRole('radio').map((radio) => (radio as HTMLInputElement).value)).toEqual(['VALID', 'EXPIRED', 'REVOKED']);
    expect(within(operations).getAllByRole('radio').map((radio) => (radio as HTMLInputElement).value)).toEqual(['READ_ONLY', 'READ_EXPORT']);
    expect(within(quantity).getByRole('radio', { name: quantityName(40) })).toBeChecked();
    expect(within(period).getByRole('radio', { name: word('main.agent.choice.period.VALID') })).toBeChecked();
    expect(within(operations).getByRole('radio', { name: word('main.agent.choice.operations.READ_EXPORT') })).toBeChecked();
  });

  it('reads the stored result of the combination first, with its age, and calls no model', async () => {
    open();

    const result = await screen.findByRole('region', { name: word('labAgent.edit.result') });
    expect(await within(result).findByText('5시간 전 실제 실행 · 새 모델 호출 없음')).toBeInTheDocument();
    expect(fetched).toContain('/api/agent-menu/ED1/OAUTH2_DELEGATED?quantity=40&period=VALID&operations=READ_EXPORT');
  });

  it('asks the portal for the combination the visitor chose and shows that stored result', async () => {
    open();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    const panel = await screen.findByRole('region', { name: word('labAgent.edit.title') });
    await user.click(within(panel).getByRole('radio', { name: quantityName(400) }));

    await vi.waitFor(() =>
      expect(fetched).toContain('/api/agent-menu/ED1/OAUTH2_DELEGATED?quantity=400&period=VALID&operations=READ_EXPORT'),
    );
  });

  it('follows the path chosen with the three values', async () => {
    open();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    const panel = await screen.findByRole('region', { name: word('labAgent.edit.title') });
    await user.click(within(panel).getByRole('radio', { name: quantityName(400) }));
    await user.click(within(panel).getByRole('radio', { name: word('main.agent.choice.period.EXPIRED') }));
    await user.click(within(panel).getByRole('radio', { name: word('main.agent.choice.operations.READ_ONLY') }));
    await user.click(within(panel).getByRole('radio', { name: new RegExp(word('labAgent.menu.path.SESSION')) }));

    await vi.waitFor(() =>
      expect(fetched).toContain('/api/agent-menu/ED1/SESSION?quantity=400&period=EXPIRED&operations=READ_ONLY'),
    );
  });

  it('says plainly when the combination has no stored result yet', async () => {
    open();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    const panel = await screen.findByRole('region', { name: word('labAgent.edit.title') });
    await user.click(within(panel).getByRole('radio', { name: quantityName(100) }));

    expect(await within(panel).findByText(word('labAgent.menu.noAnswer'))).toBeInTheDocument();
  });

  it('leads to a real run of the same choice, naming only the values that differ from the case', async () => {
    open();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    const panel = await screen.findByRole('region', { name: word('labAgent.edit.title') });
    const plain = within(panel).getByRole('link', { name: word('labAgent.edit.live') });
    expect(plain).toHaveAttribute('href', '/agent/request?case=ED1');

    await user.click(within(panel).getByRole('radio', { name: quantityName(400) }));
    await user.click(within(panel).getByRole('radio', { name: word('main.agent.choice.period.EXPIRED') }));

    expect(within(panel).getByRole('link', { name: word('labAgent.edit.live') })).toHaveAttribute(
      'href',
      '/agent/request?case=ED1&quantity=400&period=EXPIRED',
    );
    expect(within(panel).getByText(word('labAgent.edit.tickets').replace('{{n}}', '7'))).toBeInTheDocument();
  });

  it('is not in the lab when the portal offers no edit', async () => {
    delete (bodies['/api/live/config'] as Record<string, unknown>)['delegationEdit'];
    const { container } = open();

    await vi.waitFor(() => expect(fetched).toContain('/api/live/config'));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(container.textContent).toBe('');
  });
});
