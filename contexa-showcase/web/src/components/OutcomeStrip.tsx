import { useTranslation } from 'react-i18next';
import type { BusinessOutcome, ControlId } from '../domain/verdict';
import { OUTCOME_KEYS } from '../domain/verdict';
import styles from './OutcomeStrip.module.css';

interface OutcomeStripProps {
  readonly outcomes: readonly { control: ControlId; outcome: BusinessOutcome }[];
}

/** One line that shows, at a glance, which layers let the data through. */
export function OutcomeStrip({ outcomes }: OutcomeStripProps) {
  const { t } = useTranslation();
  return (
    <ol className={styles.strip} aria-label={t('outcome.strip.label')}>
      {outcomes.map(({ control, outcome }) => (
        <li key={control} className={styles.item} data-outcome={outcome} data-control={control}>
          <span className={styles.control}>{t(`control.${control}.name`)}</span>
          <span className={styles.result}>
            {t(OUTCOME_KEYS[outcome])}
          </span>
        </li>
      ))}
    </ol>
  );
}
