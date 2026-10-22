import { useTranslation } from 'react-i18next';
import type { BenchmarkCase, WrongRun } from '../../../api/benchmark';
import { ActionChip } from '../../../components/common/ActionChip';
import { useDetail } from '../../../components/detail/useDetail';
import { count } from '../../../journey/format';
import { RunCells } from './RunCells';
import styles from './Charts.module.css';

interface WrongCasesProps {
  /** The situations the server flagged as handled wrong by Contexa, of one kind, in the server's order. */
  readonly rows: readonly BenchmarkCase[];
  /** Every run Contexa got wrong, as the server listed them (newest first). */
  readonly wrongRuns: readonly WrongRun[];
  readonly nameOf: (row: BenchmarkCase) => string;
  readonly title: string;
  readonly none: string;
}

/**
 * B-6 of docs/showcase/벤치마크-구현계획.md: the situations Contexa got wrong, each with a cell per run of Contexa's result
 * and the reason the model wrote in the newest wrong run the server listed for it, kept as the original text; under it
 * the items that leaked in that run, as the server counted them, and a button to that run's record (L-41 of
 * docs/showcase/영상전-검토.md). Nothing is counted here.
 */
export function WrongCases({ rows, wrongRuns, nameOf, title, none }: WrongCasesProps) {
  const { t, i18n } = useTranslation();
  const detail = useDetail();
  return (
    <section className={styles.pairGroup} aria-label={title} data-count="exempt">
      <h3 className={styles.pairGroupTitle}>{title}</h3>
      {rows.length === 0 ? <p className={styles.noneLine}>{none}</p> : null}
      {rows.map((row) => {
        // The run the reason comes from; without a reason, the newest wrong run of the situation.
        const wrong =
          wrongRuns.find((run) => run.caseKey === row.key && run.reasoning) ??
          wrongRuns.find((run) => run.caseKey === row.key);
        return (
          <div key={row.key} className={styles.pair} data-case={row.key}>
            <div className={styles.pairLine}>
              <p className={styles.pairName}>{nameOf(row)}</p>
              <RunCells
                runs={Object.entries(row.runResults ?? {}).map(([runId, results]) => ({
                  runId,
                  result: results.D ?? 'NOT_SCORED',
                }))}
                label={t('bench.chart.pair.cells', { name: nameOf(row) })}
              />
            </div>
            {wrong?.reasoning ? (
              <p className={styles.pairValue}>
                {t('bench.chart.limits.reason')}{' '}
                <q data-original lang="en">
                  {wrong.reasoning}
                </q>
              </p>
            ) : null}
            {wrong ? (
              <div className={styles.pairRun} data-wrong-run={wrong.runId}>
                {row.classification === 'THREAT' ? (
                  <span>
                    {t('bench.chart.limits.leaked', { items: count(wrong.exposedItems, i18n.language) })}
                  </span>
                ) : null}
                <ActionChip onClick={() => detail.show(wrong.runId)} icon="search" variant="open" size="sm">
                  {t('bench.chart.limits.openRun')}
                </ActionChip>
              </div>
            ) : null}
          </div>
        );
      })}
    </section>
  );
}
