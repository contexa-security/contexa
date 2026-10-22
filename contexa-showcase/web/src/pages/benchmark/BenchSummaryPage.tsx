import { useTranslation } from 'react-i18next';
import { useUrlModal } from '../../components/common/useUrlModal';
import { BenchDetailChip, BenchScreen, BenchSource } from './BenchScreen';
import { BlindSpotProof } from './BlindSpotProof';
import { caseName, useBenchView, useReasonMatch } from './benchData';
import { BENCH_MODALS } from './benchPlace';
import { PairBars } from './charts/PairBars';
import { ProofLines } from './charts/ProofLines';
import { CellLegend } from './charts/RunCells';
import styles from './Bench.module.css';
import { sentPerCase } from './benchScope';

/** The results a pair's cells can show, in the legend's order. */
const LEGEND = ['STOPPED', 'PARTLY_STOPPED', 'MISSED', 'PASSED', 'PASSED_AFTER_CHECK', 'HALTED'] as const;

/**
 * B-1 of docs/showcase/벤치마크-구현계획.md, the benchmark's first view: the proof (4.8 of the v21 plan). What was sent in
 * one line (the situations by kind, the runs, and the decisions apart from the runs), why only the designed pairs are
 * shown, the five criteria with the portal's counts, then each designed blind-spot attack over the normal work of
 * the same conditions, a cell per run every existing approach let through with what Contexa did in it, misses
 * included. An older portal without the pairs shows the proof's tables. The scores of every method are behind "see
 * details", how the record was made behind the source line.
 */
export default function BenchSummaryPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const { view, empty, state } = useBenchView();
  const scores = useUrlModal(BENCH_MODALS.approach, ['control']);
  const method = useUrlModal(BENCH_MODALS.method);
  const reasonMatch = useReasonMatch(view?.spec?.settingHash ?? null);
  const proof = view?.blindSpot ?? null;
  const nameOf = (key: string) => {
    const row = view?.cases.find((candidate) => candidate.key === key);
    return row ? caseName(t, row, language) : key;
  };
  const charted = proof !== null && proof.totals !== undefined && (proof.pairs ?? []).length > 0;
  return (
    <BenchScreen
      view="summary"
      type="table"
      title={t('bench.chart.summary.title')}
      purpose={t('bench.chart.summary.guide')}
      more={view ? <BenchDetailChip onClick={() => scores.show({ control: 'D' })} /> : null}
      sourceLine={
        view ? <BenchSource text={t('frame.source.measured')} onOpen={() => method.show()} /> : null
      }
    >
      {state}
      {empty ? <p className={styles.line}>{t('bench.r7.empty')}</p> : null}
      {view ? (
        <>
          <p className={styles.line}>
            {t('bench.r7.summary.scope', {
              cases: view.scope.cases,
              attacks: view.caseCounts.THREAT,
              normals: view.caseCounts.NORMAL,
              open: view.caseCounts.UNCERTAIN,
              repeat: sentPerCase(view),
              runs: view.scope.runs,
            })}
          </p>
          {view.engine ? (
            <p className={styles.line}>
              {t('bench.r7.summary.decisions', { decisions: view.engine.decisions })}
            </p>
          ) : null}
          {charted && proof.totals ? (
            <>
              <p className={styles.line}>
                {t('bench.r7.summary.pairs', { count: proof.pairs?.length ?? 0 })}
              </p>
              <ProofLines
                totals={proof.totals}
                agreement={view.engine?.agreement ?? null}
                reasons={reasonMatch}
              />
              <CellLegend results={LEGEND} />
              <PairBars proof={proof} nameOf={nameOf} />
            </>
          ) : (
            <BlindSpotProof view={view} />
          )}
        </>
      ) : null}
    </BenchScreen>
  );
}
