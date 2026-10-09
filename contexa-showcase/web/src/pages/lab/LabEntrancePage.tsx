import { useTranslation } from 'react-i18next';
import { useLiveConfig } from '../../api/queries';
import { ActionChip } from '../../components/common/ActionChip';
import { NextLink } from '../../components/journey/StepParts';
import { LabScreen } from './LabScreen';
import styles from './LabPages.module.css';

/** The lab's three steps as the entrance names them (lab-0). */
const STEPS = ['case', 'change', 'send'] as const;

/**
 * L0, the lab's entrance (lab-0, 7.6): its purpose in one sentence, its three steps, what a changed condition reaches
 * (this run only) and how many runs are left today, as the portal counts them.
 */
export default function LabEntrancePage() {
  const { t } = useTranslation();
  const config = useLiveConfig().data ?? null;
  return (
    <LabScreen
      step="entrance"
      title={t('labEntrance.title')}
      purpose={t('labEntrance.purpose')}
      more={
        <ActionChip to="/lab/rules" icon="search" variant="open">
          {t('labEntrance.rules')}
        </ActionChip>
      }
      main={<NextLink to="/lab/case" label={t('labEntrance.next')} />}
    >
      <ol className={styles.threeSteps}>
        {STEPS.map((step, index) => (
          <li key={step} className={styles.threeStep}>
            <span className={styles.stepNumber} aria-hidden="true">
              {index + 1}
            </span>
            {t(`labEntrance.step.${step}`)}
          </li>
        ))}
      </ol>
      <p className={styles.scope}>
        {t('labEntrance.scope')}
        {config ? (
          <span className={styles.remaining}>{t('labEntrance.remaining', { n: config.remainingToday })}</span>
        ) : null}
      </p>
    </LabScreen>
  );
}
