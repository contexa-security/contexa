import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useLiveConfig } from '../../api/queries';
import { Icon } from '../../components/Icon';
import { NextLink } from '../../components/journey/StepParts';
import { count } from '../../journey/format';
import { WALK_STEPS } from './labPlace';
import { LabScreen } from './LabScreen';
import styles from './LabScreens.module.css';

/**
 * The lab's entrance (화면재편 R7, T1): what the lab is for, the five steps of its walk in one numbered list by the
 * names and numbers the top bar shows on each step (V-30), what a changed condition reaches (only the request sent
 * now) with the requests left today as the portal counts them, and the one other way in the lab, the rule
 * tightening, which sends nothing. The main button starts the walk.
 */
export default function LabEntrancePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const config = useLiveConfig().data ?? null;
  return (
    <LabScreen
      step="entrance"
      type="T1"
      title={t('lab.r7.entrance.title')}
      purpose={t('lab.r7.entrance.guide')}
      back={null}
      main={<NextLink to="/lab/case" label={t('lab.r7.entrance.next')} />}
    >
      <ol className={styles.walk} aria-label={t('lab.r7.entrance.steps')}>
        {WALK_STEPS.map((step, index) => (
          <li key={step} className={styles.walkStep}>
            <span className={styles.walkMark} aria-hidden="true">
              {index + 1}
            </span>
            {t(`lab.r7.step.${step}`)}
          </li>
        ))}
      </ol>
      <p className={styles.line}>
        {t('lab.r7.entrance.scope')}
        {config ? (
          <>
            {' '}
            <span className={styles.strong}>
              {t('lab.r7.entrance.remaining', { n: count(config.remainingToday, language) })}
            </span>
          </>
        ) : null}
      </p>
      <p className={styles.path}>
        <span>{t('lab.r7.entrance.rulesLead')}</span>
        <Link to="/lab/rules" className={styles.pathLink}>
          {t('lab.r7.entrance.rules')}
          <Icon name="arrowRight" />
        </Link>
      </p>
    </LabScreen>
  );
}
