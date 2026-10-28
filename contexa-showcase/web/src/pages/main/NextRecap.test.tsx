import type { ReactElement } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { RecapLine } from '../../api/journey';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import AgentNextPage from './AgentNextPage';
import PersonNextPage from './PersonNextPage';

const KO: Readonly<Record<string, string>> = ko;

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
/** The agent cases the portal opens; null when it lists none. */
let agentCases: readonly unknown[] | null = null;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  runs = [];
  agentCases = null;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 2, step: 'attack-result', differences: [] },
          runs,
          predictions: [],
        },
        ...(agentCases ? { '/api/live/config': { agentCases } } : {}),
      };
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open(path: string, element: ReactElement) {
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

const PERSON = (from: string) => open(`/person/next?from=${from}`, <PersonNextPage />);
const AGENT = () => open('/agent/next', <AgentNextPage />);

/**
 * The line of what the visitor just saw, on the next-choosers (구현계획 1절): the group covers' "지난 주제에서 확인한 것"
 * moved here, still made of the visitor's own run, so it names a result only when the run recorded it.
 * Its cases are the covers' own (docs/showcase 최종화면-구현계획 F0-7, 화면설계 4.5, IN-6).
 */
describe('the line of what the visitor just saw', () => {
  it("names a result of the case only from the visitor's own run", async () => {
    PERSON('attack');
    expect(await screen.findByText(word('cover.3.past.none'))).toBeInTheDocument();
  });

  it("says the stop of the visitor's attack run as it was recorded", async () => {
    runs = [run('S13', 'ESCALATE', 0)];
    PERSON('attack');
    expect(await screen.findByText(word('cover.3.past.ESCALATE'))).toBeInTheDocument();
  });

  it('says the attack went through when it did, and no data was kept in', async () => {
    runs = [run('S13', 'ALLOW', 480)];
    PERSON('attack');
    expect(await screen.findByText(word('cover.3.past.through'))).toBeInTheDocument();
  });

  // Review before the guide videos (2026-10-21, P-05): the split names what Contexa did on each side, not "held".
  it('says the split by the device in what Contexa did on each side', async () => {
    runs = [run('S13', 'CHALLENGE', 0), run('S13T', 'ALLOW', 480, { D: 'PASSED' })];
    PERSON('normal');
    const split = word('cover.5.past.split')
      .replace('{{attack}}', word('cover.5.past.attack.CHALLENGE'))
      .replace('{{owner}}', word('cover.5.past.owner.PASSED'));
    expect(await screen.findByText(split)).toBeInTheDocument();
    expect(split).toContain('추가 인증을 요구했고');
    expect(split).not.toContain('붙잡');
  });

  it('names a block of the attack as a block in the split', async () => {
    runs = [run('S13', 'BLOCK', 0), run('S13T', 'ALLOW', 480, { D: 'PASSED_AFTER_CHECK' })];
    PERSON('normal');
    const split = word('cover.5.past.split')
      .replace('{{attack}}', word('cover.5.past.attack.BLOCK'))
      .replace('{{owner}}', word('cover.5.past.owner.PASSED_AFTER_CHECK'));
    expect(await screen.findByText(split)).toBeInTheDocument();
  });

  it('names no split before both sides of the pair were sent', async () => {
    runs = [run('S13T', 'ALLOW', 480, { D: 'PASSED' })];
    PERSON('normal');
    expect(await screen.findByText(word('cover.5.past.none'))).toBeInTheDocument();
  });

  it("says what the visitor's own insider run recorded (IN-6)", async () => {
    const passed = { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'PARTLY_STOPPED' };
    runs = [run('S16', 'ESCALATE', 1, passed)];
    PERSON('insider');
    expect(await screen.findByText(word('cover.6.past.held').replace('{{n}}', '1'))).toBeInTheDocument();
  });

  // Review before the guide videos (2026-10-21): the insider's first document allowed, the second blocked.
  it('says the insider run was held when Contexa stopped it after its first judgment allowed', async () => {
    const partly = { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'PARTLY_STOPPED' };
    runs = [run('S16', 'ALLOW', 2, partly)];
    PERSON('insider');
    expect(await screen.findByText(word('cover.6.past.held').replace('{{n}}', '2'))).toBeInTheDocument();
  });

  it('names no insider result before the visitor sent one', async () => {
    PERSON('insider');
    expect(await screen.findByText(word('cover.6.past.none'))).toBeInTheDocument();
  });

  // docs/agent A7-3 (화면설계 4.5): the line says what the visitor's business agent run recorded.
  it("says what the visitor's own business agent run recorded", async () => {
    runs = [run('T5', '', 0, { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'STOPPED' })];
    AGENT();
    expect(await screen.findByText(word('cover.7.past.held'))).toBeInTheDocument();
  });

  it('says the agent run went through when Contexa let it through, and nothing before a run', async () => {
    runs = [run('T5', '', 0, { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'MISSED' })];
    AGENT();
    expect(await screen.findByText(word('cover.7.past.through'))).toBeInTheDocument();
  });

  it('names no agent result before the visitor sent one', async () => {
    AGENT();
    expect(await screen.findByText(word('cover.7.past.none'))).toBeInTheDocument();
  });

  // 구현계획 NW-4: the agent's chooser opens more cases than the main one, and the line names the one just finished.
  describe("when the visitor chose another of the agent's cases", () => {
    const THREAT_BLOCKED = { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'STOPPED' };
    const normalWork = (business: Readonly<Record<string, string>>) => ({
      ...run('N1', 'ALLOW', 12, business),
      classification: 'NORMAL',
    });

    beforeEach(() => {
      agentCases = [
        { key: 'M10A', title: { ko: '회사 기록에 없는 위임' }, classification: 'THREAT', subject: 'AGENT' },
        { key: 'N1', title: { ko: '주간 보고서' }, classification: 'NORMAL', subject: 'AGENT' },
      ];
    });

    it('names the latest agent run, not only the main case', async () => {
      runs = [
        run('T5', '', 0, THREAT_BLOCKED),
        run('M10A', '', 0, { ...THREAT_BLOCKED, D: 'MISSED' }),
      ];
      AGENT();
      expect(await screen.findByText(word('cover.7.past.through'))).toBeInTheDocument();
    });

    it('says a normal work case went through without claiming a miss', async () => {
      runs = [run('T5', '', 0, THREAT_BLOCKED), normalWork({ A: 'PASSED', B: 'PASSED', C1: 'PASSED', C2: 'PASSED', D: 'PASSED' })];
      AGENT();
      expect(await screen.findByText(word('cover.7.past.normal'))).toBeInTheDocument();
      expect(screen.queryByText(word('cover.7.past.through'))).toBeNull();
    });

    it('says so when Contexa stopped a normal work case', async () => {
      runs = [normalWork({ A: 'PASSED', B: 'PASSED', C1: 'PASSED', C2: 'PASSED', D: 'STOPPED' })];
      AGENT();
      expect(await screen.findByText(word('cover.7.past.normalStopped'))).toBeInTheDocument();
    });
  });
});
