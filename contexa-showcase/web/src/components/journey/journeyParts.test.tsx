import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render as plainRender, screen } from '@testing-library/react';
import type { ReactElement, ReactNode } from 'react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import { GlossaryModal, Term, TermScope } from '../common/Glossary';
import { Modal } from '../common/Modal';
import { SourceMark } from '../common/SourceMark';
import { CumulativeMeter } from '../inside/CumulativeMeter';
import { DecisionDetail, InsidePanel } from '../inside/InsidePanel';
import { actStart, screenAt, type Route as JourneyRoute, type Screen } from '../../journey/journey';
import { ActEndCard, TeaserBand } from './Cards';
import { GoalChips, IdentityDefinition, IdentityLine, JourneyBar, JustSaw, RoleBanner } from './JourneyParts';
import { ActionBar, NextLink } from './StepParts';

// The place band and the action area read where the visitor is from the server's journey; here it is set per test.
const place = vi.hoisted(() => ({
  current: {
    route: 'DEFAULT' as JourneyRoute,
    screen: null as Screen | null,
    differences: [] as readonly number[],
    skip: null as Screen | null,
  },
}));
vi.mock('../../journey/useJourneyPlace', () => ({ useJourneyPlace: () => place.current }));

function placeAt(path: string, differences: readonly number[]) {
  const screen = screenAt('DEFAULT', path);
  place.current = {
    route: 'DEFAULT',
    screen,
    differences,
    skip: screen?.act && screen.act < 4 ? actStart((screen.act + 1) as 2 | 3 | 4) : null,
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
        'Contexa · 로그인 이후 요청마다, 평소 모습과 회사 기록으로 판단하는 AI 보안 라이브러리',
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        'Contexa는 로그인 이후의 요청마다, 그 사람의 평소 모습과 회사 기록으로 판단하는 AI 보안 라이브러리입니다.',
      ),
    ).toBeInTheDocument();
  });

  it('leads a past act to its start, spells out only the current act and lists its screens as steps', async () => {
    placeAt('/intro/how/rules', [1, 2, 4, 5]);
    at('/intro/how/rules', <JourneyBar />);
    expect(screen.getByRole('link', { name: /막 1 처음으로/ })).toHaveAttribute('href', '/');
    // The tab's own name; phones show the same question again over the steps (jsdom applies no media query).
    expect(screen.getAllByText('진짜 직원이면 통과한다')[0]?.closest('[aria-current]')).toHaveAttribute(
      'aria-current',
      'step',
    );
    expect(screen.queryByText('어떻게 알고, 언제 막나')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /막 3/ })).not.toBeInTheDocument();
    // The steps are the act's screens in the order the "next" button walks them.
    const steps = screen.getByRole('list', { name: '막 2 · 진짜 직원이면 통과한다의 단계' });
    expect(steps).toHaveTextContent('상황비교판단실행결과근거7공개 규칙8본인 확인9후속 지도10정리');
    expect(screen.getByText('공개 규칙').closest('li')).toHaveAttribute('aria-current', 'step');

    await userEvent.click(screen.getByRole('button', { name: '확인한 Contexa 차이 4/6 · 카드 열기' }));
    expect(screen.getByTestId('where')).toHaveTextContent('/intro/how/rules?modal=differences');
    expect(screen.getByText('요청마다 판단')).toBeInTheDocument();
    expect(screen.getByText('? 진짜 직원이면')).toBeInTheDocument();
    expect(screen.getByText('막 2에서 확인합니다')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '닫기' }));
    expect(screen.getByTestId('where')).toHaveTextContent(/^\/intro\/how\/rules$/);
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
      /^5방금 본 차이의심받은 진짜 직원이 치른 비용은 코드 한 번, 업무는 0.05초 만에/,
    );
    expect(notes[1]).toHaveTextContent(/^6다시 보는 차이무엇을 배우고/);
    expect(screen.getByRole('status')).toHaveTextContent(
      '역할이 바뀌었습니다 · 이번엔 당신이 진짜 Administrator A입니다',
    );
  });
});

/** The curiosity chain (0-3, C-10) and the act-end card (act-end, C-11). */
describe('cards', () => {
  it('puts the question band right over the one main button, with skip beside it and back on the left', () => {
    placeAt('/try/attacker/result', []);
    at(
      '/try/attacker/result',
      <ActionBar
        back={{ to: '/try/attacker/run', label: '이전 · 실행' }}
        teaser={
          <TeaserBand
            copy={{
              question: '왜 막혔을까?',
              teaser: '걸린 사실 3가지',
              teaserItem: {
                key: 'E1_RESULT_FACTS',
                values: { facts: 3 },
                holds: null,
                source: { kind: 'MEASUREMENT', ref: 'protocol-1' },
                missing: null,
              },
            }}
          />
        }
        main={<NextLink to="/try/attacker/reason" label="이어서 보기" />}
      />,
    );
    const area = screen.getByRole('navigation', { name: '이 화면에서 할 일' });
    expect(area).toHaveTextContent(/^다음 질문왜 막혔을까\?걸린 사실 3가지/);
    expect(screen.getByRole('button', { name: '측정' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '이어서 보기' })).toHaveAttribute('href', '/try/attacker/reason');
    expect(screen.getByRole('link', { name: '막 2로 건너뛰기' })).toHaveAttribute('href', '/try/owner/scene');
    expect(screen.getByRole('link', { name: '이전 · 실행' })).toHaveAttribute('href', '/try/attacker/run');
  });

  it("states the visitor's sentence, the definition, and the unseen differences as questions", () => {
    placeAt('/try/attacker/end', [1, 2, 4, 5]);
    at(
      '/try/attacker/after',
      <ActEndCard
        act={1}
        differences={[1, 2, 4, 5]}
        sentence="당신은 정상 비밀번호로 4,831건을 빼내려 했고, Contexa는 8.0초 판단 뒤 본인 확인을 요구해 0건에서 멈췄습니다."
        measured={false}
        runId="run-1"
        next={{ question: '진짜 직원이 하면?', teaser: '숫자 규칙은 막았습니다', teaserItem: null }}
        continueTo="/try/owner/scene"
        back={{ to: '/try/attacker/after', label: '이전 · 후속' }}
        resendAsyncTo="/try/timing/try?from=attacker"
        benchmarkTo="/benchmark"
        shareUrl="https://demo/try/attacker/after"
      />,
    );
    expect(screen.getByRole('heading', { name: '막 1 끝 · 약 3분' })).toBeInTheDocument();
    expect(screen.getByText(/0건에서 멈췄습니다/)).toBeInTheDocument();
    expect(screen.getByText('? 쓸수록')).toBeInTheDocument();
    expect(screen.getByText('막 2 · 약 3분')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '막 2 시작' })).toHaveAttribute('href', '/try/owner/scene');
    // The main button already goes where skip would, so there is no skip here.
    expect(screen.queryByRole('link', { name: '막 2로 건너뛰기' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: '비동기식으로 다시 보내기' })).toBeInTheDocument();
  });
});

/** Modal rules (common-2, C-7, C-8). */
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
    expect(box).toHaveTextContent('기록 시각 2026-10-07 06:02:43 (UTC)');
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

/** Term tooltips and the glossary (common-1, words, words2). */
describe('terms and glossary', () => {
  it('underlines a term only the first time on a screen and leads to the glossary entry', async () => {
    at(
      '/intro',
      <TermScope>
        <p>
          <Term term="permission">권한</Term>이 같으면 <Term term="permission">권한</Term>만으로는 모릅니다
        </p>
        <GlossaryModal />
      </TermScope>,
    );
    expect(screen.getAllByRole('button', { name: '권한' })).toHaveLength(1);
    await userEvent.click(screen.getByRole('button', { name: '권한' }));
    expect(screen.getByRole('tooltip')).toHaveTextContent('이 역할이 이 메뉴를 쓸 수 있는지');
    await userEvent.click(screen.getByRole('button', { name: '용어 사전에서 더 보기' }));
    expect(screen.getByTestId('where')).toHaveTextContent('modal=glossary');
    expect(screen.getByRole('heading', { name: '용어 사전' })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('용어 찾기'), '동기');
    expect(screen.getByText('판단을 마칠 때까지 응답을 붙잡아 둠')).toBeInTheDocument();
    expect(screen.queryByText('그 직원이 평소 언제, 어디서, 얼마나 요청하는지')).not.toBeInTheDocument();
  });

  it('holds every screen word of both plain-words tables, and the tooltip word of the problem screen', () => {
    // words (12 rows) and words2 (9 rows) of the screen design, then g2-concept's tooltip word.
    const words = [
      '결과',
      '계정을 훔친 사람',
      '평소 모습',
      '판정 못 함',
      '정상 업무를 막음',
      '공격을 놓침',
      '공격을 막은 비율',
      '오차 범위',
      '막',
      '판정 자세히 보기',
      '로그인 상태',
      '기록만 하는 모드',
      '동기식',
      '비동기식',
      '판단 규칙',
      'AI에게 보낸 상황',
      '과거 기록 검색',
      '앞선 판정 적용',
      '본인 확인',
      '평소 모습에 더함',
      '업무 범위',
      '권한',
    ];
    at('/?modal=glossary', <GlossaryModal />);
    const terms = screen.getAllByRole('term').map((term) => term.textContent);
    expect(terms).toHaveLength(words.length);
    expect(new Set(terms)).toEqual(new Set(words));
    expect(terms).toEqual([...terms].sort(new Intl.Collator('ko').compare));
  });
});

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
            summary: '본인 확인 요구',
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
