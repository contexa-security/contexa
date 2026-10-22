import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import type { BenchmarkRate } from '../../../api/benchmark';
import { percent, percentFixed } from '../benchPlace';
import { ChartTable } from './ChartTable';
import { useNarrow } from './useNarrow';
import styles from './Charts.module.css';

/** One approach on the scatter: how often it stopped attacks (up) against how often it blocked normal work (right). */
export interface ScatterPoint {
  readonly id: string;
  readonly label: string;
  readonly x: BenchmarkRate;
  readonly y: BenchmarkRate;
  /** Contexa: drawn larger, filled with the accent colour. */
  readonly emphasis?: boolean;
}

interface RateScatterProps {
  readonly points: readonly ScatterPoint[];
  /** What the right axis counts (normal work blocked). */
  readonly xTitle: string;
  /** What the up axis counts (attacks stopped). */
  readonly yTitle: string;
  /** The chart in one sentence, for a screen reader. */
  readonly summary: string;
  /** Which way is better, shown over the chart. */
  readonly direction: string;
  /** How to read a card's bar at phone width (the value against its range), shown over the cards. */
  readonly legend?: string;
  /** What the crosses are (the 95% interval), shown under the chart (L-39 of docs/showcase/영상전-검토.md). */
  readonly cross?: string | undefined;
  /** The runs the shares were counted over, as the server counted them, under the chart and over the cards (L-39). */
  readonly basis?: string | undefined;
}

const WIDTH = 720;
const HEIGHT = 440;
const LEFT = 88;
const RIGHT = WIDTH - 28;
const TOP = 36;
const BOTTOM = HEIGHT - 64;
const TICKS = [0, 0.25, 0.5, 0.75, 1];
// A plus, not a cross: the cross is the cells' mark for an attack let through.
const MARKS = ['square', 'diamond', 'triangle', 'plus'] as const;
type Mark = (typeof MARKS)[number] | 'circle';
const LABEL_GAP = 20;
/** How far apart the ranges of points on the same spot are drawn (B-02), and off an axis they would lie on. */
const RANGE_STEP = 4;

const xAt = (value: number) => LEFT + value * (RIGHT - LEFT);
const yAt = (value: number) => BOTTOM - value * (BOTTOM - TOP);

/** A point's mark: Contexa a filled circle, the others an outlined shape each, so no approach is told by colour alone. */
function Marker({ mark, x, y, emphasis }: { mark: Mark; x: number; y: number; emphasis: boolean }) {
  const r = emphasis ? 10 : 8;
  const className = emphasis ? styles.markEmphasis : styles.mark;
  switch (mark) {
    case 'square':
      return <rect className={className} x={x - r} y={y - r} width={2 * r} height={2 * r} />;
    case 'diamond':
      return (
        <polygon className={className} points={`${x},${y - r} ${x + r},${y} ${x},${y + r} ${x - r},${y}`} />
      );
    case 'triangle':
      return <polygon className={className} points={`${x},${y - r} ${x + r},${y + r} ${x - r},${y + r}`} />;
    case 'plus':
      return <path className={className} d={`M${x - r},${y} L${x + r},${y} M${x},${y - r} L${x},${y + r}`} />;
    default:
      return <circle className={className} cx={x} cy={y} r={r} />;
  }
}

interface Placed {
  readonly point: ScatterPoint;
  readonly mark: Mark;
  readonly cx: number;
  readonly cy: number;
}

/** The spot of a rate within 2%, the grain at which points are drawn as one. */
const spot = (value: number | null) => Math.round((value ?? 0) * 50);

/**
 * B-02 of docs/showcase/영상전-검토.md: the shift of each point's range line, so the ranges of points on the same
 * spot are drawn side by side and none lies on the axis: per group of points sharing the spot, the n-th is shifted by
 * n steps, and one more step off the axis when the spot is zero. Only the lines move; each mark stays at its value.
 */
function rangeShifts(placed: readonly Placed[], spotOf: (item: Placed) => number, away: number) {
  const groups = new Map<number, Placed[]>();
  for (const item of placed) {
    const key = spotOf(item);
    groups.set(key, [...(groups.get(key) ?? []), item]);
  }
  const shifts = new Map<string, number>();
  for (const [key, group] of groups) {
    // Contexa's line first, so it passes through its own mark.
    const ordered = [...group].sort(
      (a, b) => Number(b.point.emphasis === true) - Number(a.point.emphasis === true),
    );
    ordered.forEach((item, index) => {
      shifts.set(item.point.id, away * RANGE_STEP * (index + (key === 0 ? 1 : 0)));
    });
  }
  return shifts;
}

/**
 * Points that fall on the same spot (within 2%) share one label, saying they hold the same values, so four approaches
 * at zero do not overprint.
 */
function labels(placed: readonly Placed[], same: (n: number) => string, shifts: ReadonlyMap<string, number>) {
  const groups = new Map<string, Placed[]>();
  for (const item of placed) {
    const key = `${spot(item.point.x.rate)}:${spot(item.point.y.rate)}`;
    groups.set(key, [...(groups.get(key) ?? []), item]);
  }
  const head = (group: readonly Placed[]) => group[0] as Placed;
  const sorted = [...groups.values()].sort((a, b) => head(a).cy - head(b).cy);
  // The labels placed so far, by their line and their horizontal span (a character about 15 units wide).
  const taken: { y: number; from: number; to: number }[] = [];
  return sorted.map((group) => {
    const { cx, cy } = head(group);
    const names = group.map((item) => item.point.label).join(' · ');
    const text = group.length > 1 ? `${names} ${same(group.length)}` : names;
    const right = cx > RIGHT - 260;
    const width = text.length * 15;
    // Past the range lines drawn to the right of the mark, so the words never sit on them (B-02).
    const past = Math.max(0, ...group.map((item) => shifts.get(item.point.id) ?? 0));
    const start = cx + 12 + past;
    const from = right ? cx - 12 - width : start;
    const to = from + width;
    let y = cy - 14;
    // Only a label whose span overlaps moves this one down; one far to the side does not.
    while (taken.some((other) => Math.abs(other.y - y) < LABEL_GAP && other.from < to && from < other.to)) {
      y += LABEL_GAP;
    }
    taken.push({ y, from, to });
    return {
      key: group.map((item) => item.point.id).join('-'),
      text,
      x: right ? cx - 12 : start,
      y,
      anchor: right ? ('end' as const) : ('start' as const),
      emphasis: group.some((item) => item.point.emphasis),
    };
  });
}

/**
 * B-2 of docs/showcase/벤치마크-구현계획.md: each approach as a point, attacks stopped up and normal work blocked to the
 * right, with its 95% interval as a cross (the crosses of points on the same spot side by side, B-02 of the review);
 * the upper left is the better corner. The portal counts every rate and its interval; this only places them. At phone
 * width each approach becomes a card with two bars: the value as a bar with a mark at its end, the interval as a
 * dashed box, never a filled band that reads as the value.
 */
export function RateScatter({
  points,
  xTitle,
  yTitle,
  summary,
  direction,
  legend,
  cross,
  basis,
}: RateScatterProps) {
  const { t } = useTranslation();
  const narrow = useNarrow();
  const titleId = useId();
  let others = 0;
  const placed: Placed[] = points
    .filter((point) => point.x.rate !== null && point.y.rate !== null)
    .map((point) => ({
      point,
      mark: point.emphasis ? 'circle' : (MARKS[others++ % MARKS.length] ?? 'square'),
      cx: xAt(point.x.rate ?? 0),
      cy: yAt(point.y.rate ?? 0),
    }));
  // L-39: the value and both ends of its range with one decimal, so the numbers of a cell read alike.
  const value = (rate: BenchmarkRate) =>
    `${rate.hits}/${rate.total} · ${percentFixed(rate.rate)} (${t('bench.r7.rangeValue', {
      low: percentFixed(rate.low),
      high: percentFixed(rate.high),
    })}${rate.preliminary ? ` · ${t('bench.r7.preliminary')}` : ''})`;
  const note = [cross, basis].filter((line) => line !== undefined && line !== '').join(' ');
  // Vertical lines move right, off the up axis; horizontal ones move up, off the bottom axis (B-02).
  const xShift = rangeShifts(placed, (item) => spot(item.point.x.rate), 1);
  const yShift = rangeShifts(placed, (item) => spot(item.point.y.rate), -1);
  const table = (
    <ChartTable
      head={[t('bench.chart.approach'), yTitle, xTitle]}
      rows={points.map((point) => ({ key: point.id, cells: [point.label, value(point.y), value(point.x)] }))}
    />
  );
  if (narrow) {
    return (
      <figure className={styles.figure} data-chart="scatter" aria-label={summary}>
        <figcaption className={styles.direction}>{direction}</figcaption>
        {legend ? <p className={styles.direction}>{legend}</p> : null}
        {basis ? <p className={styles.direction}>{basis}</p> : null}
        <ul className={styles.cards} data-count="exempt">
          {points.map((point) => (
            <li
              key={point.id}
              className={point.emphasis ? styles.cardEmphasis : styles.card}
              data-point={point.id}
            >
              <p className={styles.cardName}>{point.label}</p>
              {(
                [
                  ['y', yTitle, point.y],
                  ['x', xTitle, point.x],
                ] as const
              ).map(([axis, title, rate]) => (
                <div key={axis} className={styles.cardRow}>
                  <p className={styles.cardLabel}>{title}</p>
                  <div className={styles.track} aria-hidden="true">
                    <span
                      className={styles.band}
                      style={{
                        left: `${(rate.low ?? 0) * 100}%`,
                        width: `${((rate.high ?? 0) - (rate.low ?? 0)) * 100}%`,
                      }}
                    />
                    <span
                      className={point.emphasis ? styles.fillEmphasis : styles.fill}
                      style={{ width: `${(rate.rate ?? 0) * 100}%` }}
                    />
                    <span
                      className={point.emphasis ? styles.valueMarkEmphasis : styles.valueMark}
                      data-value-mark
                      style={{ left: `calc(${(rate.rate ?? 0) * 100}% - ${(rate.rate ?? 0) * 0.25}rem)` }}
                    />
                  </div>
                  <p className={styles.cardValue}>{value(rate)}</p>
                </div>
              ))}
            </li>
          ))}
        </ul>
      </figure>
    );
  }
  return (
    <figure className={styles.figure} data-chart="scatter">
      <figcaption className={styles.direction}>{direction}</figcaption>
      <svg
        className={styles.svg}
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-labelledby={titleId}
        data-count="exempt"
      >
        <title id={titleId}>{summary}</title>
        {TICKS.map((tick) => (
          <g key={tick}>
            <line className={styles.grid} x1={xAt(tick)} x2={xAt(tick)} y1={TOP} y2={BOTTOM} />
            <line className={styles.grid} x1={LEFT} x2={RIGHT} y1={yAt(tick)} y2={yAt(tick)} />
            <text className={styles.tick} x={xAt(tick)} y={BOTTOM + 22} textAnchor="middle">
              {percent(tick)}
            </text>
            <text className={styles.tick} x={LEFT - 10} y={yAt(tick) + 5} textAnchor="end">
              {percent(tick)}
            </text>
          </g>
        ))}
        <line className={styles.axis} x1={LEFT} x2={RIGHT} y1={BOTTOM} y2={BOTTOM} />
        <line className={styles.axis} x1={LEFT} x2={LEFT} y1={TOP} y2={BOTTOM} />
        <text className={styles.axisTitle} x={(LEFT + RIGHT) / 2} y={HEIGHT - 12} textAnchor="middle">
          {xTitle}
        </text>
        <text className={styles.axisTitle} x={LEFT} y={TOP - 20} textAnchor="start">
          {yTitle}
        </text>
        {placed.map(({ point, cx, cy }) => {
          const across = cy + (yShift.get(point.id) ?? 0);
          const up = cx + (xShift.get(point.id) ?? 0);
          return (
            <g key={`range-${point.id}`} className={point.emphasis ? styles.rangeEmphasis : styles.range}>
              <line x1={xAt(point.x.low ?? 0)} x2={xAt(point.x.high ?? 0)} y1={across} y2={across} />
              <line
                x1={up}
                x2={up}
                y1={yAt(point.y.low ?? 0)}
                y2={yAt(point.y.high ?? 0)}
                data-range-x={up}
              />
            </g>
          );
        })}
        {placed.map(({ point, mark, cx, cy }) => (
          <g key={`mark-${point.id}`} data-point={point.id}>
            <Marker mark={mark} x={cx} y={cy} emphasis={point.emphasis === true} />
          </g>
        ))}
        {labels(placed, (n) => t('bench.chart.approaches.same', { n }), xShift).map((label) => (
          <text
            key={label.key}
            className={label.emphasis ? styles.labelEmphasis : styles.label}
            x={label.x}
            y={label.y}
            textAnchor={label.anchor}
          >
            {label.text}
          </text>
        ))}
      </svg>
      {note ? (
        <p className={styles.direction} data-chart-note>
          {note}
        </p>
      ) : null}
      {table}
    </figure>
  );
}
