import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render as plainRender, screen } from '@testing-library/react';
import type { ReactElement, ReactNode } from 'react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import { Modal } from '../common/Modal';
import { SourceMark } from '../common/SourceMark';
import { CumulativeMeter } from '../inside/CumulativeMeter';
import { DecisionDetail, InsidePanel } from '../inside/InsidePanel';
import {
  nextScreen,
  previousScreen,
  screenAt,
  TOPICS,
  type Route as JourneyRoute,
  type Screen,
} from '../../journey/journey';
import { AppHeader } from '../AppHeader';
import { GoalChips, IdentityDefinition, IdentityLine, JustSaw, RoleBanner } from './JourneyParts';
import { ActionBar, NextLink } from './StepParts';

// The place band and the action area read where the visitor is from the server's journey; here it is set per test.
const place = vi.hoisted(() => ({
  current: {
    route: 'DEFAULT' as JourneyRoute,
    screen: null as Screen | null,
    differences: [] as readonly number[],
  },
}));
vi.mock('../../journey/useJourneyPlace', () => ({ useJourneyPlace: () => place.current }));
// The frame reports the place to the server and reads the visitor; here both answer from the place set per test.
vi.mock('../../journey/useJourneyPosition', () => ({
  useJourneyPosition: () => ({
    ...place.current,
    next: place.current.screen ? nextScreen('DEFAULT', place.current.screen.path) : null,
    previous: place.current.screen ? previousScreen('DEFAULT', place.current.screen.path) : null,
    see: () => Promise.resolve(),
  }),
}));
vi.mock('../../api/queries', async (original) => ({
  ...(await original<typeof import('../../api/queries')>()),
  useVisitor: () => ({ isSuccess: true }),
  useStats: () => ({ data: { runs: { today: 316 }, engineDecisions: 7658 } }),
}));

function placeAt(path: string, differences: readonly number[]) {
  const screen = screenAt('DEFAULT', path);
  place.current = {
    route: 'DEFAULT',
    screen,
    differences,
  };
}

beforeAll(async () => {
  await i18n.changeLanguage('ko');
});

/** The parts read the portal through react-query (the source tag reads a run's recorded time), as in the app. */
function render(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return plainRender(ui, {
    wrapper: ({ children }: { readonly children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    ),
  });
}

function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
}

function at(path: string, element: React.ReactNode) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="*" element={element} />
      </Routes>
      <Where />
    </MemoryRouter>,
  );
}

/** The thread devices (thread slide, C-9): the same identity words everywhere, the badge and its six cards. */
describe('thread devices', () => {
  it('keeps the short line and the long definition as written in decision 11', () => {
    render(
      <>
        <IdentityLine />
        <IdentityDefinition />
      </>,
    );
    expect(
      screen.getByText(
        'Contexa · 로그인 이후 요청마다, 평소 행동 패턴과 회사 업무 기록으로 판단하는 AI 보안 라이브러리',
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        'Contexa는 로그인 이후의 요청마다, 그 사람의 평소 행동 패턴과 회사 업무 기록으로 판단하는 AI 보안 라이브러리입니다.',
      ),
    ).toBeInTheDocument();
  });

  it("shows the track's name and its six steps, the finished ones ticked and the current one named, and the rest in the menu (NW-6)", async () => {
    placeAt('/normal/console', []);
    at('/normal/console', <AppHeader />);
    const steps = screen.getByRole('list', { name: '사람 체험의 여섯 단계' });
    // the track's chip and the six steps
    expect(steps.querySelectorAll('li')).toHaveLength(7);
    expect(steps).toHaveTextContent('사람');
    expect(steps.querySelectorAll('[data-state="done"]')).toHaveLength(2);
    expect(steps.querySelector('[aria-current="step"]')).toHaveTextContent('실행');
    await userEvent.click(screen.getByRole('button', { name: '메뉴' }));
    const menu = screen.getByRole('navigation', { name: '메뉴' });
    expect(menu).toHaveTextContent(
      '처음부터 다시더 알아보기실험실벤치마크도입하기개인정보 안내용어 사전English로 보기',
    );
  });

  // Review before the guide videos (2026-10-21): the top numbers had no unit (P-13); the steps of the track are named in
  // both languages, the agent's track by its own name (NW-6).
  it('counts the top numbers with their units and names the steps of a track in both languages', async () => {
    placeAt('/agent/request', []);
    const { unmount } = at('/agent/request', <AppHeader />);
    expect(screen.getByText(/오늘 방문자 실행/)).toHaveTextContent('오늘 방문자 실행 316회 · 누적 판단 7,658건');
    expect(
      screen.getByRole('list', { name: '에이전트 체험의 여섯 단계' }).querySelector('[aria-current="step"]'),
    ).toHaveTextContent('예측');
    unmount();
    await i18n.changeLanguage('en');
    try {
      at('/agent/request', <AppHeader />);
      const steps = screen.getByRole('list', { name: i18n.t('top.steps', { track: i18n.t('top.track.A') }) });
      expect(steps.querySelector('[aria-current="step"]')).toHaveTextContent('Predict');
      expect(steps).toHaveTextContent('Agent');
    } finally {
      await i18n.changeLanguage('ko');
    }
  });

  it('draws no steps on a screen both tracks share (the start, the deeper hub, the wrap-up)', () => {
    placeAt('/', []);
    at('/', <AppHeader />);
    expect(screen.queryByRole('list', { name: /여섯 단계/ })).toBeNull();
  });

  // Review before the guide videos (2026-10-21, P-33): the nine-step screen read only as the learning topic.
  it("names a 'learn more' screen after its topic and its place in it", () => {
    place.current = { ...place.current, screen: null, more: true } as typeof place.current;
    at('/intro/how', <AppHeader />);
    expect(screen.getByText(/학습이 쌓이는 과정/)).toHaveTextContent(i18n.t('more.name.g-how'));
    for (const topic of TOPICS) {
      for (const each of topic.screens) {
        expect(i18n.exists(`more.name.${each.id}`), each.id).toBe(true);
      }
    }
  });

  it('names the goals, the difference just seen and a role change in the same words everywhere', () => {
    render(
      <>
        <GoalChips differences={[3, 5]} />
        <JustSaw difference={5} sentence="e2Check" values={{ seconds: '0.05' }} />
        <JustSaw difference={6} sentence="learnAfter" again />
        <RoleBanner role="owner" name="Administrator A" />
      </>,
    );
    expect(screen.getByText('정당한 업무는 통과')).toBeInTheDocument();
    const notes = screen.getAllByRole('note');
    expect(notes[0]).toHaveTextContent(
      /^5방금 본 차이의심받은 정상 사용자가 치른 비용은 코드 한 번, 업무는 0.05초 만에/,
    );
    expect(notes[1]).toHaveTextContent(/^6다시 보는 차이무엇을 배우고/);
    expect(screen.getByRole('status')).toHaveTextContent(
      '역할이 바뀌었습니다 · 이번엔 당신이 진짜 Administrator A입니다',
    );
  });
});

/** The redesigned frame's action bar and the part wrap-up (화면재편-기획안 5절, T8; R-2, R-6). */
describe('frame', () => {
  it('has only the way back and one main button, and draws no teaser or skip even when given one', () => {
    placeAt('/try/attacker/result', []);
    at(
      '/try/attacker/result',
      <ActionBar
        back={{ to: '/try/attacker/run', label: '이전' }}
        teaser={<p>예고 카드</p>}
        main={<NextLink to="/try/attacker/reason" label="다음: 왜 막았을까?" />}
      />,
    );
    const area = screen.getByRole('navigation', { name: '이 화면에서 할 일' });
    expect(area).toHaveTextContent(/^이전다음: 왜 막았을까\?$/);
    expect(screen.getByRole('link', { name: '다음: 왜 막았을까?' })).toHaveAttribute(
      'href',
      '/try/attacker/reason',
    );
    expect(screen.getByRole('link', { name: '이전' })).toHaveAttribute('href', '/try/attacker/run');
    expect(screen.queryByText('예고 카드')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /건너뛰기/ })).not.toBeInTheDocument();
  });
});

describe('modal', () => {
  it('moves focus to its title, and closes on Esc and on its button', async () => {
    let closed = 0;
    render(
      <>
        <button type="button">opener</button>
        <Modal open title="제목" onClose={() => (closed += 1)}>
          내용
        </Modal>
      </>,
    );
    expect(screen.getByRole('heading', { name: '제목' })).toHaveFocus();
    await userEvent.keyboard('{Escape}');
    await userEvent.click(screen.getByRole('button', { name: '닫기' }));
    expect(closed).toBeGreaterThanOrEqual(1);
  });
});

/** Source tags (source slide, C-2). */
describe('source tag', () => {
  it('opens in place with the source, the run, the time in UTC and the original line', async () => {
    render(
      <SourceMark
        kind="ENGINE"
        runId="run-a81f8672e2c2"
        step={1}
        recordedAt="2026-10-07T06:02:43.678Z"
        original='"riskScore": 0.6'
      />,
    );
    await userEvent.click(screen.getByRole('button', { name: '기록' }));
    const box = screen.getByRole('group', { name: '이 값의 출처' });
    expect(box).toHaveTextContent('엔진 판정 기록');
    expect(box).toHaveTextContent('실행 run-a81f8672e2c2 · 요청 1');
    expect(box).toHaveTextContent('기록 시각 2026-10-07 06:02:43(세계 표준시)');
    expect(box).toHaveTextContent('"riskScore": 0.6');
  });

  it('downloads the stored records of the step as one file and shows its SHA-256', async () => {
    const fetched: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) => {
        fetched.push(url);
        return Promise.resolve(new Response(JSON.stringify({ url }), { status: 200 }));
      }),
    );
    const created = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:record');
    vi.spyOn(URL, 'revokeObjectURL').mockReturnValue(undefined);
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockReturnValue(undefined);
    render(
      <SourceMark
        kind="ENGINE"
        runId="run-a81f8672e2c2"
        step={1}
        record={{ runId: 'run-a81f8672e2c2', step: 1 }}
      />,
    );
    await userEvent.click(screen.getByRole('button', { name: '기록' }));
    await userEvent.click(screen.getByRole('button', { name: '실행 기록 내려받기(SHA-256)' }));
    expect(await screen.findByText(/^내려받은 파일의 SHA-256: [0-9a-f]{64}$/)).toBeInTheDocument();
    expect(fetched).toEqual([
      // Opening the box reads the run's recorded time; the download then reads the step's three records.
      '/api/runs/run-a81f8672e2c2/score',
      '/api/runs/run-a81f8672e2c2/steps/1/anatomy',
      '/api/runs/run-a81f8672e2c2/score',
      '/api/runs/run-a81f8672e2c2/steps/1/exchanges',
    ]);
    expect(created).toHaveBeenCalledTimes(1);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// Term tooltips and the glossary: components/common/Glossary.test.tsx (R7, RO-6).

/** The inside-view panel and the cumulative meter (panel, meter slides). */
describe('inside view', () => {
  it('lights the nine cells and opens a clicked cell below itself', async () => {
    render(
      <InsidePanel
        cells={[
          { id: 'request', state: 'done', summary: '새벽 3:17 · 4,831건 반출' },
          { id: 'usual', state: 'done', summary: '다른 점 3개' },
          { id: 'company', state: 'done' },
          { id: 'history', state: 'done' },
          { id: 'prompt', state: 'done' },
          { id: 'judgement', state: 'done' },
          {
            id: 'decision',
            state: 'decision',
            summary: '추가 인증 요구',
            detail: (
              <DecisionDetail
                plain="민감한 자료를 평소와 다르게, 승인 없이 내보내려 합니다"
                original="High-sensitivity access departs from the established personal baseline without a required approval; challenge is required."
                cited={['baseline', 'sensitivity', 'approval']}
                riskScore={null}
                confidence={null}
                inspector={{ met: 2, total: 17, names: [] }}
              />
            ),
          },
          { id: 'followUp', state: 'waiting' },
          { id: 'learning', state: 'waiting' },
        ]}
      />,
    );
    const panel = screen.getByRole('complementary', { name: 'Contexa 안에서 지금' });
    expect(panel).toHaveTextContent('다른 점 3개');
    const [decisionCell] = screen.getAllByRole('button', { name: /판정/ });
    if (!decisionCell) {
      throw new Error('The decision cell is missing');
    }
    await userEvent.click(decisionCell);
    expect(screen.getAllByText('검사기가 본 불리한 조건 17개 중 2개 충족')[0]).toBeInTheDocument();
    expect(screen.getAllByText('값 없음')).toHaveLength(2);
  });

  it('writes a dash with its reason where the engine did not analyse again', () => {
    render(
      <CumulativeMeter
        caption="공격 · 담당이 아닌 고객 레코드 연속 조회 5건"
        rows={[
          { request: 1, observations: 21, deltas: 2, verdict: 'CHALLENGE', riskScore: 0.65, prior: false },
          { request: 2, observations: null, deltas: null, verdict: null, riskScore: null, prior: true },
        ]}
      />,
    );
    expect(screen.getByText('앞선 판정으로 거부')).toBeInTheDocument();
    expect(screen.getByText(/새로 분석하지 않아 값이 없다는 뜻입니다/)).toBeInTheDocument();
  });
});
