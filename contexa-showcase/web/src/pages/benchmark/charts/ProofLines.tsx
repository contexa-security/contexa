import { useTranslation } from 'react-i18next';
import type { BlindSpotTotals, ModelAgreement } from '../../../api/benchmark';
import styles from './Charts.module.css';

interface ProofLinesProps {
  readonly totals: BlindSpotTotals;
  readonly agreement: ModelAgreement | null;
  readonly reasons: { readonly hits: number; readonly total: number } | null;
}

/**
 * B-1 of docs/showcase/벤치마크-구현계획.md: the five proof criteria of the v21 plan (0.1, G1 to G5), each named in words
 * ("기준 1", P-30 of docs/showcase/영상전-검토.md) as what it checks (never that it held, V-21) and the portal's counts.
 * No mark of success is drawn: the counts say it, misses included.
 */
export function ProofLines({ totals, agreement, reasons }: ProofLinesProps) {
  const { t } = useTranslation();
  const lines: readonly { readonly id: string; readonly value: string | null }[] = [
    { id: 'g1', value: t('bench.chart.proof.ofRuns', { n: totals.attackAllPassed, of: totals.attackRuns }) },
    { id: 'g2', value: t('bench.chart.proof.ofRuns', { n: totals.normalAllPassed, of: totals.normalRuns }) },
    {
      id: 'g3',
      value: t('bench.chart.proof.g3Value', {
        stopped: totals.contexaStopped,
        fully: totals.contexaFullyStopped,
        attacks: totals.attackAllPassed,
        passed: totals.contexaPassed,
        normals: totals.normalAllPassed,
      }),
    },
    {
      id: 'g4',
      value:
        agreement && agreement.modelAnswered > 0
          ? t('bench.chart.proof.g4Value', {
              as: agreement.asAnswered,
              answered: agreement.modelAnswered,
              held: agreement.held,
            })
          : null,
    },
    {
      id: 'g5',
      value: reasons && reasons.total > 0 ? t('bench.chart.proof.ofReasons', reasons) : null,
    },
  ];
  return (
    <ol className={styles.proofLines} aria-label={t('bench.chart.proof.title')}>
      {lines.map((line, index) => (
        <li key={line.id} className={styles.proofLine} data-proof={line.id}>
          <span className={styles.proofId} data-label>
            {t('bench.chart.proof.label', { n: index + 1 })}
          </span>
          <span className={styles.proofText}>{t(`bench.chart.proof.${line.id}`)}</span>
          <span className={styles.proofValue}>{line.value ?? t('bench.chart.proof.none')}</span>
        </li>
      ))}
    </ol>
  );
}
