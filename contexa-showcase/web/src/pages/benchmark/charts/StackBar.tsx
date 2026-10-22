import { useTranslation } from 'react-i18next';
import { count } from '../../../journey/format';
import { ChartTable } from './ChartTable';
import styles from './Charts.module.css';

/**
 * What a segment means, told by colour, mark and word together: stopped, stopped after some items left, data leaked,
 * work halted, and the tones that carry no judgement (another kind, the kind "other", a named explanation).
 */
export type StackTone =
  'safe' | 'partial' | 'loss' | 'halt' | 'neutral' | 'otherHatch' | 'accent' | 'accentHatch' | 'quiet';

const GLYPHS: Readonly<Record<StackTone, string>> = {
  safe: '●',
  partial: '◐',
  loss: '✕',
  halt: '■',
  neutral: '▪',
  otherHatch: '◌',
  accent: '◆',
  accentHatch: '◇',
  quiet: '·',
};

export interface StackSegment {
  readonly key: string;
  readonly label: string;
  readonly count: number;
  readonly tone: StackTone;
  /** A mark of its own in place of the tone's (an explanation's id). */
  readonly mark?: string;
}

export interface StackRow {
  readonly key: string;
  readonly label: string;
  readonly segments: readonly StackSegment[];
}

interface StackBarProps {
  readonly rows: readonly StackRow[];
  /** The chart in one sentence, for a screen reader. */
  readonly summary: string;
  /** The header of the rows' column in the table. */
  readonly rowHead: string;
  /** A kind's count in the legend of a single bar ("16회"); the dictionary's "n times" by default. */
  readonly countLabel?: (n: number) => string;
  /**
   * What a wide segment shows inside: its mark and count (the default), or its word and count for short words
   * (P-22 of docs/showcase/영상전-검토.md: "정상 업무 8", never "H1 8").
   */
  readonly inside?: 'mark' | 'label';
}

/** A segment wide enough for its mark and count to be read inside it. */
const WIDE_ENOUGH = 0.08;

/** A segment wide enough for its word and count. */
const WIDE_FOR_WORDS = 0.2;

/**
 * B-4 and B-5 of docs/showcase/벤치마크-구현계획.md: each row a 100% bar of the portal's counts, a segment per kind in
 * the given order, its mark (or word) and count inside when there is room; with several rows the segments too narrow
 * for that are named under their bar (B-15). The legend names every kind with a swatch of its segment, and the table
 * holds every count. Widths follow the counts; no number is made here.
 */
export function StackBar({ rows, summary, rowHead, countLabel, inside = 'mark' }: StackBarProps) {
  const { t, i18n } = useTranslation();
  const label = countLabel ?? ((n: number) => t('bench.chart.times', { n: count(n, i18n.language) }));
  const kinds = rows
    .flatMap((row) => row.segments)
    .filter((segment, index, all) => all.findIndex((other) => other.key === segment.key) === index);
  const mark = (segment: StackSegment) => segment.mark ?? GLYPHS[segment.tone];
  const words = (segment: StackSegment, share: number) => {
    const n = count(segment.count, i18n.language);
    if (inside === 'label' && share >= WIDE_FOR_WORDS) {
      return `${segment.label} ${n}`;
    }
    return share >= WIDE_ENOUGH ? `${mark(segment)} ${n}` : null;
  };
  return (
    <figure className={styles.figure} data-chart="stack">
      <div className={styles.stackRows} role="img" aria-label={summary} data-count="exempt">
        {rows.map((row) => {
          const total = row.segments.reduce((sum, segment) => sum + segment.count, 0);
          const shown = row.segments.filter((segment) => segment.count > 0);
          const small = shown.filter((segment) => total > 0 && segment.count / total < WIDE_ENOUGH);
          return (
            <div key={row.key} className={styles.stackRow} data-row={row.key}>
              {rows.length > 1 || row.label ? <p className={styles.stackLabel}>{row.label}</p> : null}
              <div className={styles.stack} aria-hidden="true">
                {shown.map((segment) => {
                  const text = total > 0 ? words(segment, segment.count / total) : null;
                  return (
                    <span
                      key={segment.key}
                      className={styles.segment}
                      data-tone={segment.tone}
                      data-kind={segment.key}
                      style={{ flexGrow: segment.count }}
                    >
                      {text !== null ? (
                        // On a plain chip, so the count reads on a hatched segment too.
                        <span className={styles.segmentLabel}>{text}</span>
                      ) : null}
                    </span>
                  );
                })}
              </div>
              {rows.length > 1 && small.length > 0 ? (
                <p className={styles.stackSmall} aria-hidden="true" data-small={row.key}>
                  {t('bench.chart.stack.small', {
                    items: small
                      .map((segment) =>
                        t('bench.chart.stack.item', {
                          label: segment.label,
                          n: count(segment.count, i18n.language),
                        }),
                      )
                      .join(' · '),
                  })}
                </p>
              ) : null}
            </div>
          );
        })}
      </div>
      <ul className={styles.legend} data-count="exempt">
        {kinds.map((kind) => (
          <li key={kind.key} className={styles.legendItem} data-tone={kind.tone} data-kind={kind.key}>
            <span className={styles.legendSwatch} data-tone={kind.tone} aria-hidden="true">
              {mark(kind)}
            </span>
            {kind.label}
            {rows.length === 1 ? <span className={styles.legendCount}>{label(kind.count)}</span> : null}
          </li>
        ))}
      </ul>
      <ChartTable
        head={[rowHead, ...kinds.map((kind) => kind.label)]}
        rows={rows.map((row) => ({
          key: row.key,
          cells: [
            row.label,
            ...kinds.map((kind) =>
              String(row.segments.find((segment) => segment.key === kind.key)?.count ?? 0),
            ),
          ],
        }))}
      />
    </figure>
  );
}
