import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import type { AnalysisBin } from '../../../api/benchmark';
import { count, seconds } from '../../../journey/format';
import { ChartTable } from './ChartTable';
import styles from './Charts.module.css';

interface HistogramProps {
  readonly bins: readonly AnalysisBin[];
  readonly p50Ms: number | null;
  readonly p95Ms: number | null;
  /** The chart in one sentence, for a screen reader. */
  readonly summary: string;
}

const WIDTH = 720;
const HEIGHT = 300;
const LEFT = 16;
const RIGHT = WIDTH - 16;
const TOP = 44;
const BOTTOM = HEIGHT - 48;

/** A bin edge in whole seconds when it is one ("0~5초", P-23 of docs/showcase/영상전-검토.md). */
const edge = (ms: number) => (ms % 1000 === 0 ? String(ms / 1000) : seconds(ms));

/** A marked time to the hundredth, so 29.958 s never reads as the 30 s edge of its bin (13절 of the review). */
const exact = (ms: number) => (ms / 1000).toFixed(2);

/** Whether a time falls in a bin (the last bin is open-ended). */
const holds = (bin: AnalysisBin, ms: number | null) =>
  ms !== null && ms >= bin.fromMs && (bin.toMs === null || ms < bin.toMs);

/**
 * B-4 of docs/showcase/벤치마크-구현계획.md: how long the decisions took, as the portal counted them into its bins, a
 * bar per bin with its count; the bins holding the median and the 95th percentile carry their mark.
 */
export function Histogram({ bins, p50Ms, p95Ms, summary }: HistogramProps) {
  const { t, i18n } = useTranslation();
  const titleId = useId();
  const highest = Math.max(1, ...bins.map((bin) => bin.decisions));
  const step = (RIGHT - LEFT) / Math.max(1, bins.length);
  const range = (bin: AnalysisBin) =>
    bin.toMs === null
      ? t('bench.chart.time.from', { from: edge(bin.fromMs) })
      : t('bench.chart.time.range', { from: edge(bin.fromMs), to: edge(bin.toMs) });
  return (
    <figure className={styles.figure} data-chart="histogram">
      <svg
        className={styles.svg}
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-labelledby={titleId}
        data-count="exempt"
      >
        <title id={titleId}>{summary}</title>
        <line className={styles.axis} x1={LEFT} x2={RIGHT} y1={BOTTOM} y2={BOTTOM} />
        {bins.map((bin, index) => {
          const x = LEFT + index * step;
          const height = (bin.decisions / highest) * (BOTTOM - TOP);
          const marks = [
            holds(bin, p50Ms) ? t('bench.chart.time.p50', { s: exact(p50Ms ?? 0) }) : null,
            holds(bin, p95Ms) ? t('bench.chart.time.p95', { s: exact(p95Ms ?? 0) }) : null,
          ].filter((mark): mark is string => mark !== null);
          return (
            <g key={bin.fromMs} data-bin={bin.fromMs}>
              <rect className={styles.bar} x={x + 6} y={BOTTOM - height} width={step - 12} height={height} />
              <text className={styles.barValue} x={x + step / 2} y={BOTTOM - height - 6} textAnchor="middle">
                {count(bin.decisions, i18n.language)}
              </text>
              <text className={styles.tick} x={x + step / 2} y={BOTTOM + 22} textAnchor="middle">
                {range(bin)}
              </text>
              {marks.map((mark, at) => (
                <text
                  key={mark}
                  className={styles.labelEmphasis}
                  x={x + step / 2}
                  y={TOP - 24 + at * 18}
                  textAnchor="middle"
                >
                  {`▼ ${mark}`}
                </text>
              ))}
            </g>
          );
        })}
      </svg>
      <ChartTable
        head={[t('bench.chart.time.bin'), t('bench.chart.time.decisions')]}
        rows={bins.map((bin) => ({
          key: String(bin.fromMs),
          cells: [range(bin), count(bin.decisions, i18n.language)],
        }))}
      />
    </figure>
  );
}
