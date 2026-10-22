import { useTranslation } from 'react-i18next';
import { Icon } from '../../components/Icon';
import { routeFlow } from '../../components/journey/flow';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import styles from './HowPage.module.css';

/** The nine steps in the order a request passes them (the same nine as the decision details' judgment process). */
const STEPS = [
  'request',
  'usual',
  'company',
  'history',
  'prompt',
  'judgement',
  'decision',
  'followUp',
  'learning',
] as const;

/**
 * Screen 3-2, how Contexa judges (화면재편 T7): one figure of the nine steps every request passes, top to bottom, each
 * with its name and what it does in a few words, and one line under it saying that what is learned becomes the usual
 * for the next request. The figure is read, not pressed (R-2). The old "existing security against Contexa" panels
 * belong to 5-0 and are not drawn here (their words stay in the dictionary).
 */
export default function HowPage() {
  const { t } = useTranslation();
  const flow = routeFlow(t, useJourneyPosition());
  return (
    <RouteScreen
      title={t('screen.3-2.title')}
      purpose={t('screen.3-2.guide')}
      back={flow.back}
      main={flow.next}
    >
      <ol className={styles.steps} aria-label={t('p3.how.figure')}>
        {STEPS.map((id, index) => (
          <li key={id} className={styles.step}>
            {/* The list gives the order to screen readers; the number is drawn for the eye. */}
            <span className={styles.number} aria-hidden="true">
              {index + 1}
            </span>
            <span className={styles.name}>{t(`p3.how.step.${id}.name`)}</span>
            <span className={styles.text}>{t(`p3.how.step.${id}.text`)}</span>
          </li>
        ))}
      </ol>
      <p className={styles.loop}>
        <Icon name="refresh" className={styles.loopIcon} />
        {t('p3.how.loop')}
      </p>
    </RouteScreen>
  );
}
