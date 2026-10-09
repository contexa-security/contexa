import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { usePublicSettings } from '../../api/settings';
import { ActionChip } from '../../components/common/ActionChip';
import { Modal } from '../../components/common/Modal';
import { SourceMark } from '../../components/common/SourceMark';
import { Icon } from '../../components/Icon';
import { ApproachSettings } from '../../components/inside/ApproachSettings';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { CONTROL_ORDER, type ControlId } from '../../domain/verdict';
import styles from './ApproachesPage.module.css';

/**
 * G3, five approaches (g3-five, 7.4): what each approach sees and what it cannot see, in the order and the names every
 * later screen uses. Pressing a row opens this demo's real settings of that approach as the running stack publishes
 * them.
 */
export default function ApproachesPage() {
  const { t } = useTranslation();
  const settings = usePublicSettings();
  const [open, setOpen] = useState<ControlId | null>(null);
  return (
    <RouteScreen
      title={t('approaches.title')}
      purpose={t('approaches.purpose')}
      source={
        settings.data ? (
          <SourceMark kind="CASE">
            {t('approaches.source', { version: settings.data.ruleVersion ?? '-' })}
          </SourceMark>
        ) : null
      }
      more={
        <ActionChip to="/benchmark/limits" icon="chart" variant="open">
          {t('approaches.limits')}
        </ActionChip>
      }
    >
      <p className={styles.hint}>{t('approaches.hint')}</p>
      <ol className={styles.rows} aria-label={t('approaches.title')}>
        {CONTROL_ORDER.map((control) => (
          <li key={control}>
            <button
              type="button"
              className={styles.row}
              data-contexa={control === 'D' || undefined}
              onClick={() => setOpen(control)}
            >
              <span className={styles.name}>{t(`control.${control}.name`)}</span>
              <span className={styles.sees}>
                <Icon name="check" className={styles.seesIcon} />
                <span className={styles.label}>{t('approaches.sees')}</span>
                {t(`approaches.${control}.sees`)}
              </span>
              <span className={styles.misses}>
                <Icon name="cross" className={styles.missesIcon} />
                <span className={styles.label}>{t('approaches.misses')}</span>
                {t(`approaches.${control}.misses`)}
              </span>
              <Icon name="chevronRight" className={styles.open} />
            </button>
          </li>
        ))}
      </ol>
      <Modal
        open={open !== null}
        onClose={() => setOpen(null)}
        title={open ? t('settings.title', { name: t(`control.${open}.name`) }) : ''}
      >
        {open && settings.data ? <ApproachSettings control={open} settings={settings.data} /> : null}
        {open && settings.isError ? <p>{t('settings.unavailable')}</p> : null}
      </Modal>
    </RouteScreen>
  );
}
