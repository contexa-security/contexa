import { useTranslation } from 'react-i18next';
import { ActionChip } from '../../components/common/ActionChip';
import { DifferenceMark, IdentityDefinition } from '../../components/journey/JourneyParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { DIFFERENCES } from '../../journey/journey';
import styles from './IntroPage.module.css';

/**
 * G1, the introduction (g1-start, 7.5): the question, the definition, the six differences still to see as dashed
 * circles, and the three ways on: step by step from the start (the main button, the concept path), straight into try 1
 * on the default route (D-33), or the benchmark only.
 */
export default function IntroPage() {
  const { t } = useTranslation();
  return (
    <RouteScreen
      title={t('intro.title')}
      purpose={t('intro.purpose')}
      nextLabel={t('intro.next')}
      skip={false}
      start={
        <>
          <ActionChip to="/try/attacker/scene?route=default" icon="play">
            {t('intro.try')}
          </ActionChip>
          <ActionChip to="/benchmark" icon="chart">
            {t('intro.benchmark')}
          </ActionChip>
        </>
      }
    >
      <IdentityDefinition />
      <section className={styles.differences} aria-labelledby="intro-differences">
        <h2 id="intro-differences" className={styles.title}>
          {t('intro.differences')}
        </h2>
        <ol className={styles.list} aria-labelledby="intro-differences">
          {DIFFERENCES.map((difference) => (
            <li key={difference} className={styles.item}>
              <DifferenceMark difference={difference} seen={false} />
              {t(`difference.${difference}`)}
            </li>
          ))}
        </ol>
      </section>
    </RouteScreen>
  );
}
