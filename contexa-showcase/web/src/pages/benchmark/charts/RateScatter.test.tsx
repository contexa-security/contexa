import { render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { BenchmarkRate } from '../../../api/benchmark';
import i18n from '../../../i18n';
import { required } from '../../../test/required';
import { RateScatter, type ScatterPoint } from './RateScatter';

const rate = (hits: number, total: number, low: number, high: number): BenchmarkRate => ({
  hits,
  total,
  rate: hits / total,
  low,
  high,
  preliminary: false,
});

/** Five approaches as the portal counts them on the blind-spot suite: four at zero, Contexa up and left. */
const POINTS: readonly ScatterPoint[] = [
  { id: 'A', label: '방화벽', x: rate(0, 20, 0, 0.161), y: rate(0, 25, 0, 0.133) },
  { id: 'B', label: '로그인 인증', x: rate(0, 20, 0, 0.161), y: rate(0, 25, 0, 0.133) },
  { id: 'C1', label: '고정 규칙', x: rate(0, 20, 0, 0.161), y: rate(0, 25, 0, 0.133) },
  { id: 'C2', label: '승인 기록 규칙 *', x: rate(0, 20, 0, 0.161), y: rate(0, 25, 0, 0.133) },
  { id: 'D', label: 'Contexa', x: rate(5, 20, 0.112, 0.469), y: rate(18, 25, 0.524, 0.857), emphasis: true },
];

function open() {
  return render(
    <RateScatter
      points={POINTS}
      xTitle="정상 업무를 막은 비율"
      yTitle="공격을 막은 비율"
      summary="다섯 방식의 공격 막음과 정상 업무 막음"
      direction="왼쪽 위로 갈수록 좋습니다"
      legend="막대와 끝의 표식: 측정값"
      cross="십자 막대는 흔들릴 수 있는 범위(95% 구간)입니다."
      basis="공격 25회, 정상 업무 20회를 보낸 기록입니다."
    />,
  );
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the approaches scatter', () => {
  it('draws each approach where its rates put it, one label for the points that fall together', () => {
    const { container } = open();
    expect(screen.getByRole('img', { name: '다섯 방식의 공격 막음과 정상 업무 막음' })).toBeInTheDocument();
    expect(container.querySelectorAll('[data-point]')).toHaveLength(5);
    // Four approaches at zero share one label that says they are the same; Contexa has its own.
    const svg = container.querySelector('svg');
    expect(svg).toHaveTextContent('방화벽 · 로그인 인증 · 고정 규칙 · 승인 기록 규칙 * (4개 방식 같은 값)');
    expect(svg).toHaveTextContent('Contexa');
    // B-02 of docs/showcase/영상전-검토.md: the ranges of points on the same spot are drawn side by side, none on the
    // axis, so none hides another.
    const vertical = Array.from(container.querySelectorAll('[data-range-x]'), (line) =>
      Number(line.getAttribute('data-range-x')),
    );
    expect(new Set(vertical).size).toBe(5);
    expect(vertical.every((x) => x > 88)).toBe(true);
    // The up axis is titled across, over the axis, not turned on its side.
    const title = Array.from(container.querySelectorAll('text')).find(
      (text) => text.textContent === '공격을 막은 비율',
    );
    expect(title?.getAttribute('transform')).toBeNull();
    // Contexa's point sits where 72% up and 25% right put it (viewBox: x 88..692, y 376..36).
    const contexa = container.querySelector('[data-point="D"] circle');
    expect(Number(contexa?.getAttribute('cx'))).toBeCloseTo(88 + 0.25 * 604, 5);
    expect(Number(contexa?.getAttribute('cy'))).toBeCloseTo(376 - 0.72 * 340, 5);
  });

  it('holds the same values as a table, counts and intervals as the portal sent them', () => {
    open();
    const row = screen.getByRole('row', { name: /Contexa/ });
    expect(within(row).getByText('18/25 · 72.0% (52.4%~85.7%)')).toBeInTheDocument();
    expect(within(row).getByText('5/20 · 25.0% (11.2%~46.9%)')).toBeInTheDocument();
    // L-39 of docs/showcase/영상전-검토.md: every share of a cell with one decimal, so a range never reads 0%~16.1%.
    const firewall = screen.getByRole('row', { name: /방화벽/ });
    expect(within(firewall).getByText('0/20 · 0.0% (0.0%~16.1%)')).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(6);
  });

  it('says under the chart what the crosses are and over how many runs the shares were counted', () => {
    const { container } = open();
    // L-39: the meaning of the range (the 95% interval) and the runs counted, under the drawing.
    const note = required(container.querySelector('[data-chart-note]'), 'the note under the chart');
    expect(note).toHaveTextContent(
      '십자 막대는 흔들릴 수 있는 범위(95% 구간)입니다. 공격 25회, 정상 업무 20회를 보낸 기록입니다.',
    );
    expect(
      required(container.querySelector('svg'), 'the chart').compareDocumentPosition(note) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it('becomes one card per approach at phone width, with the same values', () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: true,
      media: query,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }));
    const { container } = open();
    expect(container.querySelector('svg')).toBeNull();
    const card = container.querySelector('[data-point="D"]') as HTMLElement;
    expect(within(card).getByText('18/25 · 72.0% (52.4%~85.7%)')).toBeInTheDocument();
    expect(container.querySelectorAll('li[data-point]')).toHaveLength(5);
    // B-02: a mark at the value itself, so 0/20 with its range up to 16.1% never reads as 16%; and a legend.
    const firewall = container.querySelector('[data-point="A"]') as HTMLElement;
    expect(firewall.querySelectorAll('[data-value-mark]')).toHaveLength(2);
    expect(screen.getByText('막대와 끝의 표식: 측정값')).toBeInTheDocument();
    // L-39: the runs counted are said at phone width too.
    expect(screen.getByText('공격 25회, 정상 업무 20회를 보낸 기록입니다.')).toBeInTheDocument();
  });
});
