import { useTranslation } from 'react-i18next';
import styles from './HourBars.module.css';

interface HourBarsProps {
  /** Learned requests per hour of the day, index 0 to 23, as the engine's baseline holds them. */
  readonly hours: readonly number[];
  /** An hour to point at (the request's own hour), drawn as a line so it never reads as an amount. */
  readonly mark?: number | null;
  /** The words under the marked hour. */
  readonly markLabel?: string;
}

const TICKS = [0, 6, 12, 18, 23];

/**
 * The 24 hours of a day with the learned count of each as a bar (the engine's baseline), and one hour marked by a line
 * with its label: where the request falls against what was learned. The screen counts nothing; the bars are the
 * record's numbers.
 */
export function HourBars({ hours, mark = null, markLabel }: HourBarsProps) {
  const { t } = useTranslation();
  const peak = Math.max(1, ...hours);
  return (
    <figure className={styles.figure}>
      <div
        className={styles.bars}
        role="img"
        aria-label={hours.map((count, hour) => t('hourBars.bar', { hour, count })).join(', ')}
      >
        {hours.map((count, hour) => (
          <span
            key={hour}
            className={styles.bar}
            data-empty={count === 0 || undefined}
            style={{ blockSize: count === 0 ? undefined : `${Math.max(8, (count / peak) * 100)}%` }}
          />
        ))}
        {mark !== null ? (
          <span
            className={styles.mark}
            style={{ insetInlineStart: `${((mark + 0.5) / hours.length) * 100}%` }}
          >
            {markLabel ? <span className={styles.markLabel}>{markLabel}</span> : null}
          </span>
        ) : null}
      </div>
      <div className={styles.ticks} aria-hidden="true">
        {TICKS.map((hour) => (
          <span
            key={hour}
            className={styles.tick}
            style={{ insetInlineStart: `${((hour + 0.5) / hours.length) * 100}%` }}
          >
            {t('hourBars.tick', { hour })}
          </span>
        ))}
      </div>
    </figure>
  );
}
