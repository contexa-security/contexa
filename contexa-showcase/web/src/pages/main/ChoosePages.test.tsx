import type { ReactElement } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import { rememberTrack } from '../../journey/trackMemory';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import AgentChoosePage from './AgentChoosePage';
import AgentNextPage from './AgentNextPage';
import DeeperPage from './DeeperPage';
import PersonChoosePage from './PersonChoosePage';
import TrackChoosePage from './TrackChoosePage';
import PersonNextPage from './PersonNextPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

const STATE = {
  route: 'DEFAULT',
  act: 2,
  step: 'attack-result',
  differences: [],
  predictions: {},
  updatedAt: '2026-10-27T00:00:00Z',
};

/** A run the visitor sent of the stolen account's case: every existing control missed it, Contexa stopped it, no data left. */
const ATTACK_RUN = {
  runId: 'run-1',
  scenarioKey: 'S13',
  classification: 'THREAT',
  status: 'COMPLETED',
  lab: false,
  business: { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'STOPPED' },
  engineAction: 'BLOCK',
  exposedItems: 0,
  correct: true,
  requestedItems: 480,
  steps: 1,
};

let bodies: Record<string, unknown>;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  window.sessionStorage.clear();
  bodies = {
    '/api/visitor': { predictions: {} },
    '/api/journey': { state: STATE, runs: [], predictions: [] },
    '/api/live/config': {
      agentCases: [
        {
          key: 'M10A',
          title: { ko: '회사 기록에 없는 위임', en: 'A delegation the company has no record of' },
          classification: 'THREAT',
          subject: 'AGENT',
        },
        {
          key: 'N1',
          title: { ko: '주간 보고서', en: 'Weekly report' },
          classification: 'NORMAL',
          subject: 'AGENT',
        },
        {
          key: 'T5',
          title: { ko: '위임 만료 뒤', en: 'After expiry' },
          classification: 'THREAT',
          subject: 'AGENT',
        },
        {
          key: 'X9',
          title: { ko: '이름만 있는 사례', en: 'A case with a title only' },
          classification: 'THREAT',
          subject: 'AGENT',
        },
      ],
    },
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function at(path: string, element: ReactElement) {
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

function cards(): HTMLElement[] {
  return screen.getAllByRole('link').filter((link) => link.hasAttribute('data-choice'));
}

/** The cards a visitor sees at once: the ones not under a closed fold. */
function visibleCards(): HTMLElement[] {
  return cards().filter((card) => card.closest('details:not([open])') === null);
}

/** The spoken length of a choosing screen's own copy: what a visitor reads on its first view, spaces not counted. */
function spoken(...keys: string[]): number {
  return keys
    .map((key) => word(key))
    .join('')
    .replace(/\s/g, '').length;
}

/** What a visitor reads on a choosing screen at first sight: everything in the main area, spaces not counted. */
function readable(): number {
  return (document.querySelector('main')?.textContent ?? '').replace(/\s/g, '').length;
}

/** The cards that carry a line under their title. */
function withLine(): string[] {
  return cards()
    .filter((card) => card.querySelector('[class*="sub"]') !== null)
    .map((card) => card.getAttribute('data-choice') ?? '');
}

describe('the text budget of the choosing screens (구현계획 AC-N1: 120 characters at first sight)', () => {
  const AGENT_RUN = {
    ...ATTACK_RUN,
    runId: 'run-t5',
    scenarioKey: 'T5',
  };

  it("keeps H-6 within it with the line of what the visitor just saw, and only the suggested card has a line", async () => {
    bodies['/api/journey'] = { state: STATE, runs: [ATTACK_RUN], predictions: [] };
    at('/person/next?from=attack', <PersonNextPage />);
    await waitFor(() => expect(screen.getByText(word('cover.3.past.BLOCK'))).toBeInTheDocument());
    expect(readable()).toBeLessThanOrEqual(120);
    expect(withLine()).toEqual(['opposite']);
  });

  it("keeps A-6 within it with the line of the agent's run, and only the suggested card has a line", async () => {
    bodies['/api/journey'] = { state: STATE, runs: [AGENT_RUN], predictions: [] };
    at('/agent/next', <AgentNextPage />);
    await waitFor(() => expect(screen.getByText(word('next.recapLabel'))).toBeInTheDocument());
    expect(readable()).toBeLessThanOrEqual(120);
    expect(withLine()).toEqual(['opposite']);
  });

  it('keeps A-1 within it with every case the portal opens, each told by its title alone', async () => {
    at('/agent', <AgentChoosePage />);
    await waitFor(() => expect(cards()).toHaveLength(4));
    expect(readable()).toBeLessThanOrEqual(120);
    expect(withLine()).toEqual([]);
  });

  it("keeps D-1 within it for each track's own list, each screen told by its title alone", () => {
    at('/deeper?track=A', <DeeperPage />);
    expect(cards()).toHaveLength(6);
    expect(readable()).toBeLessThanOrEqual(120);
    expect(withLine()).toEqual([]);
  });
});

describe('C-1, which request to see first', () => {
  it('offers the AI agent and the person, in plain words, each opening its track', () => {
    at('/choose', <TrackChoosePage />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('main.C-1.title'));
    expect(screen.getByText(word('main.C-1.intro'))).toBeInTheDocument();
    expect(cards().map((card) => [card.getAttribute('data-choice'), card.getAttribute('href')])).toEqual([
      ['agent', '/agent'],
      ['person', '/person'],
    ]);
    expect(within(cards()[0] as HTMLElement).getByText(word('pick.agent.title'))).toBeInTheDocument();
    expect(word('pick.agent.title')).toContain('AI 에이전트');
  });
});

describe("H-1, the person's chooser", () => {
  it("offers three cases, each leading to that case's request screen, with the strong title and one intro line", () => {
    at('/person', <PersonChoosePage />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('main.H-1.title'));
    expect(screen.getByText(word('main.H-1.intro'))).toBeInTheDocument();
    expect(cards().map((card) => [card.getAttribute('data-choice'), card.getAttribute('href')])).toEqual([
      ['attack', '/attack/request'],
      ['normal', '/normal/request'],
      ['insider', '/insider/request'],
    ]);
  });

  it('stays inside the text budget of a choosing screen (120 characters, 28 for the title, 40 for the intro)', () => {
    expect(word('main.H-1.title').replace(/\s/g, '').length).toBeLessThanOrEqual(28);
    expect(word('main.H-1.intro').replace(/\s/g, '').length).toBeLessThanOrEqual(40);
    const all = spoken(
      'main.H-1.title',
      'main.H-1.intro',
      'choose.person.attack.title',
      'choose.person.attack.sub',
      'choose.person.normal.title',
      'choose.person.normal.sub',
      'choose.person.insider.title',
      'choose.person.insider.sub',
    );
    expect(all).toBeLessThanOrEqual(120);
  });
});

describe("A-1, the agent's chooser", () => {
  it('offers the open cases in the demo order, each leading to the give-the-work screen with the case named', async () => {
    at('/agent', <AgentChoosePage />);
    await waitFor(() => expect(cards()).toHaveLength(4));
    expect(cards().map((card) => [card.getAttribute('data-choice'), card.getAttribute('href')])).toEqual([
      ['N1', '/agent/request?case=N1'],
      ['T5', '/agent/request?case=T5'],
      ['M10A', '/agent/request?case=M10A'],
      ['X9', '/agent/request?case=X9'],
    ]);
  });

  // 구현계획 AC-N5: at most four choices in view; the rest wait under one line.
  it('shows four cases at once and keeps the others under one line', async () => {
    at('/agent', <AgentChoosePage />);
    await waitFor(() => expect(cards()).toHaveLength(4));
    expect(visibleCards().length).toBeLessThanOrEqual(4);
    bodies['/api/live/config'] = {
      agentCases: ['N1', 'T5', 'M22A', 'M10A', 'M14A'].map((key) => ({
        key,
        title: { ko: key, en: key },
        classification: 'THREAT',
        subject: 'AGENT',
      })),
    };
    cleanup();
    const { container } = at('/agent', <AgentChoosePage />);
    await waitFor(() => expect(cards()).toHaveLength(5));
    expect(visibleCards()).toHaveLength(4);
    const fold = container.querySelector('details[data-fold="choose-more"]') as HTMLDetailsElement | null;
    expect(fold).not.toBeNull();
    expect(fold?.open).toBe(false);
    expect(within(fold as HTMLElement).getAllByRole('link')).toHaveLength(1);
    expect(fold?.querySelector('[data-choice="M14A"]')).not.toBeNull();
  });

  it('words a known case in the dictionary and shows an unknown open case by its own title', async () => {
    at('/agent', <AgentChoosePage />);
    await waitFor(() => expect(cards()).toHaveLength(4));
    const known = cards().find((card) => card.getAttribute('data-choice') === 'N1') as HTMLElement;
    expect(within(known).getByText(word('choose.agent.N1.title'))).toBeInTheDocument();
    const unknown = cards().find((card) => card.getAttribute('data-choice') === 'X9') as HTMLElement;
    expect(within(unknown).getByText('이름만 있는 사례')).toBeInTheDocument();
  });

  it('still opens the track with its first case when the portal lists none', async () => {
    bodies['/api/live/config'] = {};
    at('/agent', <AgentChoosePage />);
    await waitFor(() => expect(cards()).toHaveLength(1));
    expect(cards()[0]?.getAttribute('href')).toBe('/agent/request');
  });
});

describe('H-6 and A-6, what to see next', () => {
  it('offers the opposite scene first and suggested, then a change of condition, the deeper screens and the other track, and wraps up with the main button', () => {
    at('/person/next?from=attack', <PersonNextPage />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('main.H-6.title'));
    expect(cards().map((card) => [card.getAttribute('data-choice'), card.getAttribute('href')])).toEqual([
      ['opposite', '/normal/request'],
      ['change', '/compare/change'],
      ['deeper', '/deeper?track=H'],
      ['other', '/agent'],
    ]);
    expect(cards()[0]).toHaveAttribute('data-recommended');
    expect(
      within(cards()[0] as HTMLElement).getByText(word('next.opposite.recommended')),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: new RegExp(word('main.H-6.cta')) })).toHaveAttribute(
      'href',
      '/summary',
    );
  });

  it('turns the suggestion to the other side of the pair by the case the visitor just finished', () => {
    at('/person/next?from=normal', <PersonNextPage />);
    expect(cards()[0]?.getAttribute('href')).toBe('/attack/request');
    expect(
      within(cards()[0] as HTMLElement).getByText(word('next.opposite.normal.title')),
    ).toBeInTheDocument();
  });

  it('leads the agent track to the normal work, the agent lab, the deeper screens and the person track', () => {
    at('/agent/next', <AgentNextPage />);
    expect(cards().map((card) => [card.getAttribute('data-choice'), card.getAttribute('href')])).toEqual([
      ['opposite', '/agent/request?case=N1'],
      ['change', '/lab/agent'],
      ['deeper', '/deeper?track=A'],
      ['other', '/person'],
    ]);
  });

  it("says in one line what the visitor just saw, from the visitor's own run", async () => {
    bodies['/api/journey'] = { state: STATE, runs: [ATTACK_RUN], predictions: [] };
    at('/person/next?from=attack', <PersonNextPage />);
    await waitFor(() => expect(screen.getByText(word('cover.3.past.BLOCK'))).toBeInTheDocument());
    expect(screen.getByText(word('next.recapLabel'))).toBeInTheDocument();
  });

  it('names no result the visitor did not have', async () => {
    at('/person/next?from=attack', <PersonNextPage />);
    await waitFor(() => expect(screen.getByText(word('cover.3.past.none'))).toBeInTheDocument());
  });
});

describe('D-1, the deeper hub', () => {
  it("lists the person track's deeper screens first and the ones both tracks share, and leads back to its next-chooser", () => {
    at('/deeper?track=H', <DeeperPage />);
    expect(cards().map((card) => [card.getAttribute('data-choice'), card.getAttribute('href')])).toEqual([
      ['diff', '/normal/diff'],
      ['suspected', '/normal/check'],
      ['evidence', '/evidence/map'],
      ['rules', '/compare/rule'],
      ['map', '/intro/map'],
    ]);
    expect(screen.getByRole('link', { name: word('deeper.back') })).toHaveAttribute('href', '/person/next');
  });

  it("shows four deeper screens at once in each track's list and keeps the rest under one line", () => {
    const person = at('/deeper?track=H', <DeeperPage />);
    expect(cards()).toHaveLength(5);
    expect(visibleCards()).toHaveLength(4);
    expect(person.container.querySelector('details[data-fold="choose-more"]')).not.toBeNull();
    cleanup();
    const agent = at('/deeper?track=A', <DeeperPage />);
    expect(cards()).toHaveLength(6);
    expect(visibleCards()).toHaveLength(4);
    const fold = agent.container.querySelector('details[data-fold="choose-more"]') as HTMLDetailsElement;
    expect(within(fold).getAllByRole('link')).toHaveLength(2);
  });

  it("lists the agent track's own deeper screens, the three the old agent group walked in a row", () => {
    at('/deeper?track=A', <DeeperPage />);
    expect(cards().map((card) => card.getAttribute('data-choice'))).toEqual([
      'confirm',
      'end',
      'burst',
      'evidence',
      'rules',
      'map',
    ]);
    expect(screen.getByRole('link', { name: word('deeper.back') })).toHaveAttribute('href', '/agent/next');
  });

  it('lists every deeper screen in groups for a visitor who comes without a track, leaving none of the old screens out', () => {
    bodies['/api/journey'] = { state: { ...STATE, step: 'deeper' }, runs: [], predictions: [] };
    at('/deeper', <DeeperPage />);
    const found = cards().map((card) => card.getAttribute('href'));
    for (const path of [
      '/normal/diff',
      '/normal/check',
      '/agent/confirm',
      '/agent/end',
      '/agent/burst',
      '/evidence/map',
      '/compare/rule',
      '/intro/map',
    ]) {
      expect(found, path).toContain(path);
    }
    expect(screen.getByRole('heading', { name: word('deeper.group.person') })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: word('deeper.group.agent') })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('frame.back') })).toHaveAttribute('href', '/');
  });

  // 구현계획 NW-5: the evidence, rules and map screens belong to both tracks, so coming back from one of them names no track.
  // The track is remembered where the visitor stood on it (trackMemory), not only where the hub was opened.
  it('leads back to the track the visitor stood on before, without having opened the hub with a track', () => {
    rememberTrack('A');
    bodies['/api/journey'] = { state: { ...STATE, step: '7-1' }, runs: [], predictions: [] };
    at('/deeper', <DeeperPage />);
    expect(screen.getByRole('link', { name: word('deeper.back') })).toHaveAttribute('href', '/agent/next');
  });

  it('keeps the track it was opened with when a screen both tracks share leads back to it', () => {
    const first = at('/deeper?track=H', <DeeperPage />);
    first.unmount();
    bodies['/api/journey'] = { state: { ...STATE, step: '3-1' }, runs: [], predictions: [] };
    at('/deeper', <DeeperPage />);
    expect(screen.getByRole('link', { name: word('deeper.back') })).toHaveAttribute('href', '/person/next');
    expect(cards().map((card) => card.getAttribute('data-choice'))).toContain('diff');
  });

  it('follows the other track once the visitor opened it, not the first one it remembered', () => {
    at('/deeper?track=H', <DeeperPage />).unmount();
    at('/deeper?track=A', <DeeperPage />).unmount();
    bodies['/api/journey'] = { state: { ...STATE, step: '7-1' }, runs: [], predictions: [] };
    at('/deeper', <DeeperPage />);
    expect(screen.getByRole('link', { name: word('deeper.back') })).toHaveAttribute('href', '/agent/next');
  });
});
