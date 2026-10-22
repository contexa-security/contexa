import { useTranslation } from 'react-i18next';
import { useUrlModal } from '../../components/common/useUrlModal';
import { BenchDetailChip, BenchScreen, BenchSource } from './BenchScreen';
import { caseName, useBenchView } from './benchData';
import { BENCH_MODALS } from './benchPlace';
import { CaseMap } from './charts/CaseMap';
import styles from './Bench.module.css';

/**
 * B-3 of docs/showcase/벤치마크-구현계획.md (a table view): every situation against the five approaches on one map, a
 * cell per run with its result, the server's counts of situations and of the ones Contexa got wrong over it. A
 * situation's name opens its window; "see details" opens the window at the first situation, under the name every
 * benchmark view gives its chip, and the source line opens how the record was made, as on the other views (L-40, L-42
 * of docs/showcase/영상전-검토.md). The old pages (?page=, ?tab=) are gone; such an address opens the map.
 */
export default function BenchCasesPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const benchCase = useUrlModal(BENCH_MODALS.benchCase, ['case']);
  const method = useUrlModal(BENCH_MODALS.method);
  const { view, empty, state } = useBenchView();
  const first = view?.cases[0] ?? null;
  return (
    <BenchScreen
      view="cases"
      type="table"
      title={t('bench.r7.cases.title')}
      purpose={t('bench.chart.map.guide')}
      more={first ? <BenchDetailChip onClick={() => benchCase.show({ case: first.key })} /> : null}
      sourceLine={
        first ? <BenchSource text={t('frame.source.measured')} onOpen={() => method.show()} /> : null
      }
    >
      {state}
      {empty ? <p className={styles.line}>{t('bench.r7.empty')}</p> : null}
      {view && !first ? <p className={styles.line}>{t('bench.r7.cases.none')}</p> : null}
      {view && first ? (
        <>
          <p className={styles.line}>
            {t('bench.chart.map.counts', {
              attacks: view.caseCounts.THREAT,
              attacksWrong: view.contexaWrongCases.THREAT,
              normals: view.caseCounts.NORMAL,
              normalsWrong: view.contexaWrongCases.NORMAL,
              open: view.caseCounts.UNCERTAIN,
            })}
          </p>
          <CaseMap view={view} nameOf={(row) => caseName(t, row, language)} />
          <p className={styles.note}>{t('bench.r7.footnote')}</p>
        </>
      ) : null}
    </BenchScreen>
  );
}
