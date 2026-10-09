import { useTranslation } from 'react-i18next';
import type { LaneState } from '../../domain/show';
import styles from './LeakCounters.module.css';

interface LeakCountersProps {
  /** Documents that left through the existing security (perimeter and permission check). */
  readonly existing: number;
  readonly contexa: LaneState;
  readonly total: number;
  /** Contexa's stream ended part-way on the engine's own marker. */
  readonly stopped: boolean;
}

/**
 * The two counters of the attack (docs/showcase/화면설계서.md scene 2): what left through the existing security and
 * what left through Contexa, counted from the streams of this run as they are read.
 */
export function LeakCounters({ existing, contexa, total, stopped }: LeakCountersProps) {
  const { t } = useTranslation();
  const delivered = contexa.kind === 'waiting' ? 0 : contexa.delivered;
  return (
    <div className={styles.counters}>
      <Counter label={t('show.counter.existing')} value={existing} total={total} tone="loss" />
      <Counter
        label={t('show.counter.contexa')}
        value={delivered}
        total={total}
        tone={stopped ? 'safe' : 'loss'}
        contexa
      />
    </div>
  );
}

function Counter({
  label,
  value,
  total,
  tone,
  contexa = false,
}: {
  readonly label: string;
  readonly value: number;
  readonly total: number;
  readonly tone: 'loss' | 'safe';
  readonly contexa?: boolean;
}) {
  const { t } = useTranslation();
  return (
    <div className={styles.counter} data-tone={value === 0 ? 'idle' : tone} data-contexa={contexa}>
      <span className={styles.label}>{label}</span>
      <span className={styles.caption}>{t('show.counter.leaked')}</span>
      <span className={styles.value}>
        <span className={styles.number}>{value.toLocaleString()}</span>
        <span className={styles.total}>{t('show.counter.of', { total: total.toLocaleString() })}</span>
      </span>
    </div>
  );
}
