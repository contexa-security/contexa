import { act, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import {
  Badge,
  Bar,
  Breadcrumbs,
  Button,
  ButtonLink,
  Card,
  CodeChip,
  DataTable,
  DetailPanel,
  Drawer,
  EmptyState,
  ErrorState,
  EvalBadge,
  Field,
  FlagBadge,
  Icon,
  KeyValue,
  Kpi,
  Loading,
  Modal,
  Note,
  PageHead,
  Range,
  StackedBar,
  Stepper,
  SummaryBar,
  Switch,
  TabPanel,
  Tabs,
  TextInput,
  VerdictBadge,
} from '.';

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

describe('Icon', () => {
  it('is hidden from assistive technology unless it carries its own label', () => {
    const { container } = render(<Icon name="ban" />);
    expect(container.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');
    render(<Icon name="ban" label="차단 표시" />);
    expect(screen.getByRole('img', { name: '차단 표시' })).toBeInTheDocument();
  });
});

describe('Button', () => {
  it('names its variant and size and runs its action', async () => {
    const onClick = vi.fn();
    render(
      <Button variant="primary" size="lg" icon="play" onClick={onClick}>
        요청 실행
      </Button>,
    );
    const button = screen.getByRole('button', { name: '요청 실행' });
    expect(button).toHaveAttribute('data-variant', 'primary');
    expect(button).toHaveAttribute('data-size', 'lg');
    await userEvent.click(button);
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('stays focusable when unavailable, says why, and does not run', async () => {
    const onClick = vi.fn();
    render(
      <Button onClick={onClick} disabledReason="오늘 실행 한도 도달">
        요청 실행
      </Button>,
    );
    const button = screen.getByRole('button', { name: '요청 실행' });
    expect(button).toHaveAttribute('aria-disabled', 'true');
    expect(button).toHaveAccessibleDescription('오늘 실행 한도 도달');
    await userEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
  });

  it('marks a running action busy and ignores a second press', async () => {
    const onClick = vi.fn();
    render(
      <Button busy onClick={onClick}>
        요청 실행
      </Button>,
    );
    const button = screen.getByRole('button', { name: '요청 실행' });
    expect(button).toHaveAttribute('aria-busy', 'true');
    await userEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
  });

  it('can be a link that looks like a button', () => {
    render(
      <MemoryRouter>
        <ButtonLink to="/simulate" variant="secondary" iconAfter="arrow-right">
          위협 시뮬레이션 시작
        </ButtonLink>
      </MemoryRouter>,
    );
    expect(screen.getByRole('link', { name: '위협 시뮬레이션 시작' })).toHaveAttribute('href', '/simulate');
  });
});

describe('badges', () => {
  it('show every verdict as a word with its icon, never by colour alone', async () => {
    const { container } = render(
      <>
        <VerdictBadge verdict="ALLOW" />
        <VerdictBadge verdict="CHALLENGE" showCode />
        <VerdictBadge verdict="ESCALATE" />
        <VerdictBadge verdict="BLOCK" />
        <VerdictBadge verdict="PENDING" />
        <VerdictBadge verdict="NONE" />
        <VerdictBadge verdict="PENDING" unresolved />
      </>,
    );
    const words = [...container.querySelectorAll('[data-tone]')].map((badge) => [
      badge.getAttribute('data-tone'),
      badge.textContent,
      badge.querySelectorAll('svg').length,
    ]);
    expect(words).toEqual([
      ['allow', '허용', 1],
      ['stepup', '추가 인증CHALLENGE', 1],
      ['hold', '검토 보류', 1],
      ['block', '차단', 1],
      ['none', '분석 중', 1],
      ['none', '판정 없음', 1],
      ['none', '판정 없음', 1],
    ]);
    await act(() => i18n.changeLanguage('en'));
    expect(container.querySelector('[data-tone="stepup"]')).toHaveTextContent('Step-up');
  });

  it('show evaluations without icons and deviations in the neutral flag', () => {
    const { container } = render(
      <>
        <EvalBadge result="correct" />
        <EvalBadge result="normal" />
        <EvalBadge result="partial" />
        <EvalBadge result="missed" />
        <EvalBadge result="falsePositive" />
        <FlagBadge />
        <Badge tone="line" icon="bot">
          AI 에이전트
        </Badge>
      </>,
    );
    const badges = [...container.querySelectorAll('[data-tone]')].map((badge) => [
      badge.getAttribute('data-tone'),
      badge.textContent,
      badge.querySelectorAll('svg').length,
    ]);
    expect(badges).toEqual([
      ['allow', '적중', 0],
      ['allow', '정상 처리', 0],
      ['stepup', '일부 반출 뒤 차단', 0],
      ['block', '미탐', 0],
      ['block', '오탐', 0],
      ['flag', '기준선 이탈', 1],
      ['line', 'AI 에이전트', 1],
    ]);
  });
});

describe('CodeChip', () => {
  it('copies its value and says so', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    render(<CodeChip value="run-04cdd89264f7" copy />);
    await userEvent.click(screen.getByRole('button', { name: 'run-04cdd89264f7 복사' }));
    expect(writeText).toHaveBeenCalledWith('run-04cdd89264f7');
    expect(await screen.findByText('복사됨')).toBeInTheDocument();
  });

  it('is plain text when it is not copyable', () => {
    render(<CodeChip value="S13" />);
    expect(screen.queryByRole('button')).toBeNull();
    expect(screen.getByText('S13').tagName).toBe('CODE');
  });
});

describe('page frame parts', () => {
  it('give the page one heading the route focus can land on', () => {
    render(
      <PageHead
        kicker={<Badge tone="line">위협 시뮬레이션</Badge>}
        title="계정 탈취 · 내부자 위협"
        desc="실제 판정 엔진으로 시나리오를 실행합니다."
        actions={<Button>판정 이력</Button>}
      />,
    );
    const heading = screen.getByRole('heading', { level: 1, name: '계정 탈취 · 내부자 위협' });
    expect(heading).toHaveAttribute('tabindex', '-1');
    expect(screen.getByText('실제 판정 엔진으로 시나리오를 실행합니다.')).toBeInTheDocument();
  });

  it('name a card by its title and keep the actions in its head', () => {
    render(
      <Card title="판정 분포" sub="최근 14일 · 13,733건" actions={<Button size="sm">표 보기</Button>}>
        본문
      </Card>,
    );
    const card = screen.getByRole('region', { name: '판정 분포' });
    expect(within(card).getByRole('heading', { level: 2 })).toHaveTextContent('판정 분포');
    expect(within(card).getByRole('button', { name: '표 보기' })).toBeInTheDocument();
  });

  it('show a figure with its unit and its sample on the same card', () => {
    render(<Kpi icon="activity" label="누적 판정" value="13,733" unit="건" foot="2026-10-18 ~ 10-31" />);
    const figure = screen.getByRole('group', { name: '누적 판정' });
    expect(figure).toHaveTextContent('13,733건');
    expect(figure).toHaveTextContent('2026-10-18 ~ 10-31');
  });

  it('list the summary cells as terms and values', () => {
    render(
      <SummaryBar
        label="판정 요약"
        items={[
          { label: '위험도', value: '0.43' },
          { label: '확신도', value: '0.78' },
        ]}
      />,
    );
    const terms = screen.getAllByRole('term').map((term) => term.textContent);
    const values = screen.getAllByRole('definition').map((value) => value.textContent);
    expect(terms).toEqual(['위험도', '확신도']);
    expect(values).toEqual(['0.43', '0.78']);
  });

  it('mark the current place in the breadcrumb', () => {
    render(
      <MemoryRouter>
        <Breadcrumbs
          items={[{ label: '위협 시뮬레이션', to: '/simulate' }, { label: '계정 탈취 · 내부자 위협' }]}
        />
      </MemoryRouter>,
    );
    const nav = screen.getByRole('navigation', { name: '현재 위치' });
    expect(within(nav).getByRole('link', { name: '위협 시뮬레이션' })).toHaveAttribute('href', '/simulate');
    expect(within(nav).getByText('계정 탈취 · 내부자 위협')).toHaveAttribute('aria-current', 'page');
  });
});

describe('Tabs', () => {
  function Harness() {
    const [value, setValue] = useState('result');
    return (
      <>
        <Tabs
          idBase="detail"
          label="판정 상세"
          value={value}
          onChange={setValue}
          items={[
            { id: 'result', label: '판정 결과' },
            { id: 'facts', label: '인용 사실', count: 10 },
            { id: 'seal', label: '무결성 검증' },
          ]}
        />
        <TabPanel idBase="detail" id={value}>
          {value} 내용
        </TabPanel>
      </>
    );
  }

  it('select by click and by arrow keys, with the panel named by its tab', async () => {
    render(<Harness />);
    const facts = screen.getByRole('tab', { name: '인용 사실 10' });
    await userEvent.click(facts);
    expect(facts).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tabpanel', { name: '인용 사실 10' })).toHaveTextContent('facts 내용');
    fireEvent.keyDown(facts, { key: 'ArrowRight' });
    const seal = screen.getByRole('tab', { name: '무결성 검증' });
    expect(seal).toHaveAttribute('aria-selected', 'true');
    expect(seal).toHaveFocus();
    fireEvent.keyDown(seal, { key: 'ArrowRight' });
    expect(screen.getByRole('tab', { name: '판정 결과' })).toHaveAttribute('aria-selected', 'true');
    fireEvent.keyDown(screen.getByRole('tab', { name: '판정 결과' }), { key: 'End' });
    expect(seal).toHaveAttribute('aria-selected', 'true');
    expect(screen.getAllByRole('tab').filter((tab) => tab.tabIndex === 0)).toHaveLength(1);
  });
});

describe('Stepper', () => {
  it('marks the current step and the finished ones', () => {
    render(<Stepper steps={['시나리오 확인', '실행', '판정 결과', '같은 요청 비교']} current={2} />);
    const nav = screen.getByRole('navigation', { name: '진행 단계' });
    const items = within(nav).getAllByRole('listitem');
    expect(items.map((item) => item.getAttribute('data-state'))).toEqual(['done', 'done', 'now', 'next']);
    expect(items[2]).toHaveAttribute('aria-current', 'step');
    expect(items[0]).toHaveTextContent('시나리오 확인완료');
  });
});

describe('DataTable', () => {
  const rows = [
    { id: 'a', name: '웹 방화벽', blocked: 0 },
    { id: 'b', name: 'Contexa', blocked: 3 },
  ];
  it('labels each cell for the stacked phone layout and marks the selected and highlighted rows', () => {
    render(
      <DataTable
        caption="통제별 차단 수"
        rows={rows}
        rowKey={(row) => row.id}
        selected="a"
        highlighted={(row) => row.name === 'Contexa'}
        stack
        columns={[
          { key: 'name', header: '통제', strong: true, render: (row) => row.name },
          { key: 'blocked', header: '차단', numeric: true, render: (row) => row.blocked },
        ]}
      />,
    );
    const table = screen.getByRole('table', { name: '통제별 차단 수' });
    expect(
      within(table)
        .getAllByRole('columnheader')
        .map((th) => th.textContent),
    ).toEqual(['통제', '차단']);
    const [, first, second] = within(table).getAllByRole('row') as [HTMLElement, HTMLElement, HTMLElement];
    expect(first).toHaveAttribute('aria-current', 'true');
    expect(second).not.toHaveAttribute('aria-current');
    expect(second).toHaveAttribute('data-highlight', 'true');
    expect(within(second).getAllByRole('cell')[1]).toHaveAttribute('data-k', '차단');
    expect(table).toHaveAttribute('data-stack', 'true');
  });
});

describe('content parts', () => {
  it('give a note its role and a warning its own icon', () => {
    render(
      <>
        <Note>표본 41개 시나리오 × 5회</Note>
        <Note tone="warn">이 숫자는 이전 빌드의 측정입니다</Note>
      </>,
    );
    const notes = screen.getAllByRole('note');
    expect(notes.map((note) => note.getAttribute('data-tone'))).toEqual(['neutral', 'warn']);
  });

  it('list names and values', () => {
    render(<KeyValue items={[{ label: '모델', value: 'gpt-6-luna' }]} />);
    expect(screen.getByRole('term')).toHaveTextContent('모델');
    expect(screen.getByRole('definition')).toHaveTextContent('gpt-6-luna');
  });

  it('draw a share as a meter and a distribution with its legend', () => {
    render(
      <>
        <Bar label="위험도" value={0.43} tone="link" />
        <StackedBar
          label="판정 분포"
          segments={[
            { label: '허용', value: 9932, tone: 'allow' },
            { label: '차단', value: 517, tone: 'block' },
          ]}
          format={(value) => value.toLocaleString('ko-KR')}
        />
      </>,
    );
    const meter = screen.getByRole('meter', { name: '위험도' });
    expect(meter).toHaveAttribute('aria-valuenow', '0.43');
    const legend = screen.getByRole('list', { name: '판정 분포' });
    expect(
      within(legend)
        .getAllByRole('listitem')
        .map((item) => item.textContent),
    ).toEqual(['허용 9,932', '차단 517']);
  });
});

describe('states', () => {
  it('say loading, empty and failed in words, and retry on request', async () => {
    const retry = vi.fn();
    render(
      <>
        <Loading rows={3} />
        <EmptyState />
        <ErrorState onRetry={retry} />
      </>,
    );
    expect(screen.getByRole('status')).toHaveTextContent('불러오는 중');
    expect(screen.getByText('표시할 기록 없음')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('불러오기 실패');
    await userEvent.click(screen.getByRole('button', { name: '다시 시도' }));
    expect(retry).toHaveBeenCalledTimes(1);
  });
});

describe('inputs', () => {
  it('label each control above it and tie the hint to it', () => {
    render(
      <Field label="임계값" hint="0.0 ~ 1.0">
        {(props) => <TextInput {...props} defaultValue="0.5" />}
      </Field>,
    );
    const input = screen.getByRole('textbox', { name: '임계값' });
    expect(input).toHaveAccessibleDescription('0.0 ~ 1.0');
  });

  it('switch on and off and slide within its range', async () => {
    function Harness() {
      const [on, setOn] = useState(false);
      const [value, setValue] = useState(3);
      return (
        <>
          <Switch label="휴면 계정 조건" checked={on} onChange={setOn} />
          <Range label="건수 임계값" min={1} max={10} value={value} onChange={setValue} />
        </>
      );
    }
    render(<Harness />);
    const toggle = screen.getByRole('switch', { name: '휴면 계정 조건' });
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-checked', 'true');
    const slider = screen.getByRole('slider', { name: '건수 임계값' });
    fireEvent.change(slider, { target: { value: '7' } });
    expect(slider).toHaveValue('7');
  });
});

describe('layers', () => {
  it('open a modal with its title, close it with its button and with Escape', async () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <Button onClick={() => setOpen(true)}>확인 열기</Button>
          <Modal
            open={open}
            onClose={() => setOpen(false)}
            title="동일 요청 60건 전송"
            footer={<Button variant="primary">전송</Button>}
          >
            실제 판정 비용이 듭니다.
          </Modal>
        </>
      );
    }
    render(<Harness />);
    await userEvent.click(screen.getByRole('button', { name: '확인 열기' }));
    const dialog = screen.getByRole('dialog', { name: '동일 요청 60건 전송' });
    expect(dialog).toHaveAttribute('open');
    await userEvent.click(within(dialog).getByRole('button', { name: '닫기' }));
    expect(dialog).not.toHaveAttribute('open');
    await userEvent.click(screen.getByRole('button', { name: '확인 열기' }));
    fireEvent(dialog, new Event('cancel', { cancelable: true }));
    expect(dialog).not.toHaveAttribute('open');
  });

  it('open a drawer from its side and a detail panel with its close action', async () => {
    const close = vi.fn();
    render(
      <>
        <Drawer open side="start" title="메뉴" onClose={close}>
          메뉴 항목
        </Drawer>
        <DetailPanel title="run-04cdd89264f7" onClose={close} footer={<Button>판정 상세</Button>}>
          상세
        </DetailPanel>
      </>,
    );
    expect(screen.getByRole('dialog', { name: '메뉴' })).toHaveAttribute('data-side', 'start');
    const panel = screen.getByRole('complementary', { name: 'run-04cdd89264f7' });
    await userEvent.click(within(panel).getByRole('button', { name: '닫기' }));
    expect(close).toHaveBeenCalledTimes(1);
  });
});
