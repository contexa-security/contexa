import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import snapshot from '../main/agentSnapshotFixture';
import { AgentMenuPanel } from './AgentMenuPanel';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

const NOW = Date.parse('2026-10-27T12:00:00Z');
const FIVE_HOURS_AGO = '2026-10-27T07:00:00Z';

const LISTING = {
  cases: [
    { key: 'M19A', title: { ko: '내보내기 40건을 400건으로', en: 'Forty exports become four hundred' } },
    { key: 'M14A', title: { ko: '위조한 티켓', en: 'A forged ticket' } },
  ],
  paths: ['OAUTH2_DELEGATED', 'OAUTH2_AGENT', 'SESSION'],
  items: [
    { caseKey: 'M19A', path: 'OAUTH2_DELEGATED', ranAt: FIVE_HOURS_AGO, stale: false },
    { caseKey: 'M19A', path: 'SESSION', ranAt: '2026-10-24T07:00:00Z', stale: true },
    { caseKey: 'M14A', path: 'SESSION', ranAt: FIVE_HOURS_AGO, stale: false },
  ],
};

function answer(caseKey: string, path: string, stale: boolean, ranAt: string) {
  return {
    caseKey,
    path,
    ranAt,
    stale,
    caseView: { ...snapshot.case, key: caseKey, title: { ko: `${caseKey} 사례`, en: `${caseKey} case` } },
    run: snapshot.run,
  };
}

let calls: { readonly url: string; readonly method: string }[];
let bodies: Record<string, unknown>;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  calls = [];
  bodies = {
    '/api/agent-menu': LISTING,
    '/api/agent-menu/M19A/OAUTH2_DELEGATED': answer('M19A', 'OAUTH2_DELEGATED', false, FIVE_HOURS_AGO),
    '/api/agent-menu/M19A/SESSION': answer('M19A', 'SESSION', true, '2026-10-24T07:00:00Z'),
    '/api/agent-menu/M14A/SESSION': answer('M14A', 'SESSION', false, FIVE_HOURS_AGO),
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, method: init?.method ?? 'GET' });
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
        <AgentMenuPanel />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('the agent menu (AC-4a)', () => {
  it('offers the cases and the three ways an agent sends requests, and shows the first stored answer at once', async () => {
    open();

    const cases = await screen.findByRole('radiogroup', { name: word('labAgent.menu.case') });
    expect(within(cases).getAllByRole('radio').map((radio) => (radio as HTMLInputElement).value)).toEqual([
      'M19A',
      'M14A',
    ]);
    const paths = screen.getByRole('radiogroup', { name: word('labAgent.menu.path') });
    expect(within(paths).getAllByRole('radio')).toHaveLength(3);
    expect(within(paths).getByLabelText('보내는 쪽: 위임 에이전트')).toBeInTheDocument();
    // the first combination that has a stored answer is shown, so the screen is never empty
    const result = await screen.findByRole('region', { name: word('labAgent.menu.result') });
    expect(within(result).getByText('M19A 사례')).toBeInTheDocument();
    expect(within(result).getByText('5시간 전 실제 실행 · 새 모델 호출 없음')).toBeInTheDocument();
    expect(within(result).queryByText(word('labAgent.menu.stale'))).not.toBeInTheDocument();
    // the requests and the lanes wait for the visitor's guess (or for "show it now")
    expect(within(result).queryByRole('heading', { name: word('main.6-7.lanes') })).not.toBeInTheDocument();
    expect(screen.getByRole('group', { name: word('labAgent.menu.guess') })).toBeInTheDocument();
  });

  it('shows the stored run of the chosen combination as the proof, the lanes and the requests', async () => {
    open();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    await user.click(await screen.findByRole('radio', { name: /위조한 티켓/ }));
    await user.click(screen.getByRole('radio', { name: new RegExp(word('labAgent.menu.path.SESSION')) }));

    const result = await screen.findByRole('region', { name: word('labAgent.menu.result') });
    expect(await within(result).findByText('M14A 사례')).toBeInTheDocument();
    await user.click(within(result).getByRole('button', { name: word('labAgent.menu.guess.show') }));
    expect(within(result).getByRole('heading', { name: word('main.6-7.lanes') })).toBeInTheDocument();
    expect(within(result).getByRole('table')).toBeInTheDocument();
    expect(within(result).queryByText(word('labAgent.menu.guess.right'))).not.toBeInTheDocument();
  });

  it('marks an answer that is old or ran another definition, and still shows it', async () => {
    open();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    await user.click(await screen.findByRole('radio', { name: new RegExp(word('labAgent.menu.path.SESSION')) }));

    const result = await screen.findByRole('region', { name: word('labAgent.menu.result') });
    expect(await within(result).findByText(word('labAgent.menu.stale'))).toBeInTheDocument();
    expect(within(result).getByText('3일 전 실제 실행 · 새 모델 호출 없음')).toBeInTheDocument();
    await user.click(within(result).getByRole('button', { name: word('labAgent.menu.guess.show') }));
    expect(within(result).getByRole('heading', { name: word('main.6-7.lanes') })).toBeInTheDocument();
  });

  it('says plainly when a combination has no stored answer yet', async () => {
    open();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    await user.click(await screen.findByRole('radio', { name: new RegExp(word('labAgent.menu.path.OAUTH2_AGENT')) }));

    expect(await screen.findByText(word('labAgent.menu.noAnswer'))).toBeInTheDocument();
  });

  it('lets the visitor guess first, for nothing, and tells whether the guess was right', async () => {
    open();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const guess = await screen.findByRole('group', { name: word('labAgent.menu.guess') });

    // control D stopped the stored run at its first request: "stops" is right
    await user.click(within(guess).getByRole('button', { name: word('labAgent.menu.guess.stop') }));

    expect(await screen.findByText(word('labAgent.menu.guess.right'))).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: word('main.6-7.lanes') })).toBeInTheDocument();
    await user.click(within(guess).getByRole('button', { name: word('labAgent.menu.guess.pass') }));
    expect(await screen.findByText(word('labAgent.menu.guess.wrong'))).toBeInTheDocument();
    expect(screen.queryByText(word('labAgent.menu.guess.right'))).not.toBeInTheDocument();
  });

  it('only reads: choosing and guessing never send anything but the stored answers', async () => {
    open();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    await user.click(await screen.findByRole('radio', { name: /위조한 티켓/ }));
    await user.click(screen.getByRole('radio', { name: new RegExp(word('labAgent.menu.path.SESSION')) }));
    await user.click(await screen.findByRole('button', { name: word('labAgent.menu.guess.stop') }));

    expect(calls.every((call) => call.method === 'GET' && call.url.startsWith('/api/agent-menu'))).toBe(true);
  });

  it('shows nothing of the menu when the portal has none', async () => {
    delete bodies['/api/agent-menu'];
    const { container } = open();

    await vi.waitFor(() => expect(calls.length).toBeGreaterThan(0));
    expect(container.textContent).toBe('');
  });
});
