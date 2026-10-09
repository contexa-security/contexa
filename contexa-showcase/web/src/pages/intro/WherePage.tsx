import { Trans, useTranslation } from 'react-i18next';
import { ActionChip } from '../../components/common/ActionChip';
import { Modal } from '../../components/common/Modal';
import { useUrlModal } from '../../components/common/useUrlModal';
import { Icon } from '../../components/Icon';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { ADOPT_CODE } from '../show/adoptCode';
import styles from './WherePage.module.css';

/** The steps inside the application, in the order a request passes them; the business call is last. */
const INSIDE = ['signIn', 'permission', 'rules', 'contexa', 'business'] as const;

/**
 * G3-2, where they sit (g-where, 7.4): the WAF stands outside the application at its door; sign-in, the permission
 * check, the rules and Contexa run inside the Spring application before the business call, and the application hands
 * the company records to Contexa. Contexa is a library put into the application, not a separate box; the code that
 * does it is this demo's own source, kept equal line for line by a test (adoptCode.ts).
 */
export default function WherePage() {
  const { t } = useTranslation();
  const modal = useUrlModal('where-code');
  return (
    <RouteScreen
      title={t('where.title')}
      purpose={t('where.purpose')}
      more={
        <ActionChip icon="code" variant="open" onClick={() => modal.show()}>
          {t('where.code')}
        </ActionChip>
      }
    >
      <figure className={styles.figure} aria-label={t('where.figure')}>
        <span className={styles.request}>
          <Icon name="box" />
          {t('where.request')}
        </span>
        <Icon name="arrowRight" className={styles.arrow} />
        <span className={styles.outside}>
          <span className={styles.zone}>{t('where.outside')}</span>
          <span className={styles.step}>{t('control.A.name')}</span>
        </span>
        <Icon name="arrowRight" className={styles.arrow} />
        <span className={styles.inside}>
          <span className={styles.zone}>{t('where.inside')}</span>
          <ol className={styles.steps}>
            {INSIDE.map((step) => (
              <li key={step} className={styles.step} data-step={step}>
                {t(`where.step.${step}`)}
              </li>
            ))}
          </ol>
          <span className={styles.company}>
            <Icon name="book" />
            {t('where.company')}
          </span>
        </span>
      </figure>
      <p className={styles.library}>
        <Trans
          i18nKey="where.library"
          components={{ code: <code className={styles.inline} data-original /> }}
        />
      </p>
      <p className={styles.honest}>{t('where.honest')}</p>
      <Modal open={modal.open} onClose={modal.hide} title={t('where.code')} wide>
        {ADOPT_CODE.map((excerpt) => (
          <figure key={excerpt.path} className={styles.excerpt}>
            <figcaption className={styles.excerptPath} data-original>
              {excerpt.path}
            </figcaption>
            <pre className={styles.code} data-original tabIndex={0} aria-label={excerpt.path}>
              {excerpt.lines.map((line, index) => (
                <span
                  key={index}
                  className={styles.line}
                  data-highlight={index === excerpt.highlight || undefined}
                >
                  {line}
                  {'\n'}
                </span>
              ))}
            </pre>
          </figure>
        ))}
      </Modal>
    </RouteScreen>
  );
}
