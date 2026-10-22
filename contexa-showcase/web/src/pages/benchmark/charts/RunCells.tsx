import { useTranslation } from 'react-i18next';
import { useDetail } from '../../../components/detail/useDetail';
import styles from './Charts.module.css';

/** The looks of a cell: each result its own colour and pattern (B-01 of docs/showcase/영상전-검토.md). */
type CellTone = 'safe' | 'partial' | 'loss' | 'pass' | 'passCheck' | 'halt' | 'quiet';

/**
 * A business result as a cell shows it: the deck's colour of the result (설계서 679: 막음 · 일부 유출 · 놓침/오탐 ·
 * 허용) and a mark of its own, so no result is told by colour alone and no two results share a look.
 */
const RESULT_LOOK: Readonly<Record<string, { readonly tone: CellTone; readonly glyph: string }>> = {
  STOPPED: { tone: 'safe', glyph: '●' },
  PARTLY_STOPPED: { tone: 'partial', glyph: '◐' },
  MISSED: { tone: 'loss', glyph: '✕' },
  PASSED: { tone: 'pass', glyph: '○' },
  PASSED_AFTER_CHECK: { tone: 'passCheck', glyph: '◑' },
  HALTED: { tone: 'halt', glyph: '■' },
};

const UNSCORED = { tone: 'quiet' as const, glyph: '·' };

/** A result's word: the deck's result chip name, a benchmark word for a run without a set answer. */
function resultWord(t: ReturnType<typeof useTranslation>['t'], result: string): string {
  return t(`bench.chart.cell.${result}`, {
    defaultValue: t(`main.result.${result}`, { defaultValue: result }),
  });
}

/**
 * What each cell means, in the order of the results: the legend draws the cell itself (its colour, pattern and mark),
 * so the legend and the cells look alike (B-01).
 */
export function CellLegend({ results }: { readonly results: readonly string[] }) {
  const { t } = useTranslation();
  return (
    <ul className={styles.legend} data-count="exempt" aria-label={t('bench.chart.cellLegend')}>
      {results.map((result) => {
        const look = RESULT_LOOK[result] ?? UNSCORED;
        return (
          <li key={result} className={styles.legendItem} data-tone={look.tone} data-result={result}>
            <span className={`${styles.cell} ${styles.legendCell}`} data-tone={look.tone} aria-hidden="true">
              {look.glyph}
            </span>
            {resultWord(t, result)}
          </li>
        );
      })}
    </ul>
  );
}

export interface RunCell {
  readonly runId: string;
  readonly result: string;
}

/**
 * One run per cell (B-1, B-3 of docs/showcase/벤치마크-구현계획.md): its result's colour and mark; a click opens that
 * run's evidence. The cells are not tab stops (the case's name is), as on the run matrix (FP-4).
 */
export function RunCells({
  runs,
  label,
  compact = false,
}: {
  readonly runs: readonly RunCell[];
  readonly label: string;
  /** The smaller cells of the case map. */
  readonly compact?: boolean;
}) {
  const { t } = useTranslation();
  const detail = useDetail();
  return (
    <span className={styles.cells} role="group" aria-label={label}>
      {runs.map((run) => {
        const look = RESULT_LOOK[run.result] ?? UNSCORED;
        const word = resultWord(t, run.result);
        return (
          <button
            key={run.runId}
            type="button"
            tabIndex={-1}
            className={compact ? `${styles.cell} ${styles.cellCompact}` : styles.cell}
            data-tone={look.tone}
            data-run={run.runId}
            data-dot
            data-result={run.result}
            aria-label={t('bench.chart.run', { run: run.runId, result: word })}
            title={`${run.runId} · ${word}`}
            onClick={() => detail.show(run.runId, 1)}
          >
            {look.glyph}
          </button>
        );
      })}
    </span>
  );
}
