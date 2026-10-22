import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { RecapLine } from '../../api/journey';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import BriefingPage from './BriefingPage';

const KO: Readonly<Record<string, string>> = ko;
const CELLS = ['do', 'check', 'try', 'learn'] as const;
const COVERS = [
  [2, '/attack'],
  [3, '/evidence'],
  [4, '/normal'],
  [5, '/insider'],
  [6, '/compare'],
] as const;

function word(key: string): string {
  return required(KO[key], key);
}

/** A run of the visitor as the journey lists it. */
function run(
  scenarioKey: string,
  engineAction: string,
  exposedItems: number,
  business: Readonly<Record<string, string>> = {},
): RecapLine {
  return {
    runId: `run-${scenarioKey.toLowerCase()}`,
    scenarioKey,
    classification: scenarioKey === 'S13T' ? 'NORMAL' : 'THREAT',
    status: 'COMPLETED',
    lab: false,
    business,
    engineAction,
    exposedItems,
    correct: true,
    requestedItems: 480,
    steps: 1,
  };
}

let runs: readonly RecapLine[] = [];

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  runs = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 2, step: 'attack-cover', differences: [] },
          runs,
          predictions: [],
        },
      };
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={<BriefingPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** A group's cover (T0, 최종화면-구현계획 F0-7). */
describe('the cover of a group', () => {
  it.each(COVERS)(
    'opens group %i at %s with its question, four cells and one button into the group',
    (group, path) => {
      const { container } = open(path);
      expect(container.querySelector('main')).toHaveAttribute('data-type', 'T0');
      expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word(`cover.${group}.question`));
      for (const cell of CELLS) {
        expect(screen.getByText(word(`cover.label.${cell}`))).toBeInTheDocument();
        expect(screen.getByText(word(`cover.${group}.${cell}`))).toBeInTheDocument();
      }
      const name = word(`group.${group}`);
      expect(
        screen.getByRole('link', { name: word('cover.start').replace('{{name}}', name) }),
      ).toBeInTheDocument();
    },
  );

  it("names a result of the group before only from the visitor's own run", async () => {
    open('/evidence');
    expect(await screen.findByText(word('cover.3.past.none'))).toBeInTheDocument();
  });

  it("says the stop of the visitor's attack run as it was recorded", async () => {
    runs = [run('S13', 'ESCALATE', 0)];
    open('/evidence');
    expect(await screen.findByText(word('cover.3.past.ESCALATE'))).toBeInTheDocument();
  });

  // Review before the guide videos (2026-10-21, P-05): the split names what Contexa did on each side, not "held".
  it('says the split by the device in what Contexa did on each side', async () => {
    runs = [run('S13', 'CHALLENGE', 0), run('S13T', 'ALLOW', 480, { D: 'PASSED' })];
    open('/insider');
    const split = word('cover.5.past.split')
      .replace('{{attack}}', word('cover.5.past.attack.CHALLENGE'))
      .replace('{{owner}}', word('cover.5.past.owner.PASSED'));
    expect(await screen.findByText(split)).toBeInTheDocument();
    expect(split).toContain('추가 인증을 요구했고');
    expect(split).not.toContain('붙잡');
  });

  it('names a block of the attack as a block in the split', async () => {
    runs = [run('S13', 'BLOCK', 0), run('S13T', 'ALLOW', 480, { D: 'PASSED_AFTER_CHECK' })];
    open('/insider');
    const split = word('cover.5.past.split')
      .replace('{{attack}}', word('cover.5.past.attack.BLOCK'))
      .replace('{{owner}}', word('cover.5.past.owner.PASSED_AFTER_CHECK'));
    expect(await screen.findByText(split)).toBeInTheDocument();
  });

  it("says what the visitor's own insider run recorded (IN-6)", async () => {
    const passed = { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'PARTLY_STOPPED' };
    runs = [run('S16', 'ESCALATE', 1, passed)];
    open('/compare');
    expect(await screen.findByText(word('cover.6.past.held').replace('{{n}}', '1'))).toBeInTheDocument();
  });

  // Review before the guide videos (2026-10-21): the insider's first document allowed, the second blocked.
  it('says the insider run was held when Contexa stopped it after its first judgment allowed', async () => {
    const partly = { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'PARTLY_STOPPED' };
    runs = [run('S16', 'ALLOW', 2, partly)];
    open('/compare');
    expect(await screen.findByText(word('cover.6.past.held').replace('{{n}}', '2'))).toBeInTheDocument();
  });

  it('names no insider result before the visitor sent one', async () => {
    open('/compare');
    expect(await screen.findByText(word('cover.6.past.none'))).toBeInTheDocument();
  });

  it('sets the two themes apart on their covers, marking the one it opens (IN-6)', async () => {
    const { container } = open('/insider');
    const pair = await screen.findByRole('region', { name: word('theme.title') });
    expect(pair).toHaveTextContent(word('theme.outside.line'));
    expect(pair).toHaveTextContent(word('theme.inside.line'));
    expect(container.querySelector('[data-current]')).toHaveTextContent(word('theme.inside.name'));
    // Review before the guide videos (2026-10-21, B-12): the marked card says it is the one shown, not a button.
    expect(container.querySelector('[data-current]')).toHaveTextContent(word('theme.current'));
    expect(container.querySelector('[data-other]')).toHaveTextContent(word('theme.outside.name'));
  });
});
