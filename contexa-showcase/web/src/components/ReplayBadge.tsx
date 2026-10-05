import { useTranslation } from 'react-i18next';
import styles from './ReplayBadge.module.css';

interface ReplayBadgeProps {
  readonly mode: 'replay' | 'live';
  readonly specLabel: string;
}

/** Always states whether the visitor sees a recorded real run or a live run, and which spec produced it. */
export function ReplayBadge({ mode, specLabel }: ReplayBadgeProps) {
  const { t } = useTranslation();
  return (
    <p className={styles.badge} data-mode={mode}>
      <span className={styles.dot} aria-hidden="true" />
      <span>{t(mode === 'replay' ? 'replay.badge' : 'live.badge')}</span>
      <span className={styles.separator} aria-hidden="true">
        ·
      </span>
      <span className={styles.spec}>
        <span className={styles.segment}>{t('replay.spec')}</span>{' '}
        {specLabel.split(' · ').map((segment, index) => (
          <span key={segment} className={styles.segment}>
            {index > 0 ? ' · ' : ''}
            {segment}
          </span>
        ))}
      </span>
    </p>
  );
}
