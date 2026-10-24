import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useBenchmark } from '../../api/benchmark';
import { Chip } from '../../components/main/Chip';
import { MainScreen } from '../../components/main/MainScreen';
import { dollars, seconds } from '../../journey/format';
import { OpsStrip } from './OpsStrip';
import styles from './SummaryPages.module.css';

/**
 * 8-2, what next (설계서 6-2): adopting it, with the measured decision time and cost per decision; the whole benchmark;
 * and the topics of "learn more". Picking one ends the demo.
 */
export default function NextPage() {
  const { t } = useTranslation();
  const benchmark = useBenchmark(null);
  const engine = benchmark.data?.engine ?? null;
  const scope = benchmark.data?.scope ?? null;
  return (
    <MainScreen title={t('main.8-2.title')} intro={t('main.8-2.intro')} main={null} nextNote={null}>
      {engine ? <OpsStrip engine={engine} /> : null}
      <ul className={styles.next}>
        <li className={styles.choice} data-recommended>
          <Link to="/adopt" className={styles.choiceLink}>
            <Chip kind="wait">{t('main.8-2.recommended')}</Chip>
            <b className={styles.choiceName}>{t('main.8-2.adopt')}</b>
            <span className={styles.choiceLine}>{t('main.8-2.adopt.line')}</span>
            <code className={styles.choiceCode}>
              {engine && engine.analysisP50Ms !== null && engine.costPerDecisionUsd !== null
                ? t('main.8-2.adopt.code', {
                    p50: seconds(engine.analysisP50Ms),
                    cost: dollars(engine.costPerDecisionUsd),
                  })
                : '@Protectable'}
            </code>
          </Link>
        </li>
        <li className={styles.choice}>
          <Link to="/benchmark" className={styles.choiceLink}>
            <b className={styles.choiceName}>{t('main.8-2.benchmark')}</b>
            <span className={styles.choiceLine}>
              {scope ? t('main.8-2.benchmark.line', { cases: scope.cases, runs: scope.runs }) : '…'}
            </span>
          </Link>
        </li>
        <li className={styles.choice}>
          <Link to="/more" className={styles.choiceLink}>
            <b className={styles.choiceName}>{t('main.8-2.more')}</b>
            <span className={styles.choiceLine}>{t('main.8-2.more.line')}</span>
          </Link>
        </li>
      </ul>
    </MainScreen>
  );
}
