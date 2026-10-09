import { useTranslation } from 'react-i18next';
import type { LiveLayer } from '../../../api/types';
import type { ControlId } from '../../../domain/verdict';
import { count, seconds } from '../../../journey/format';
import styles from '../Experience.module.css';
import { verdictKey } from './liveRun';

export interface BarProps {
  readonly control: ControlId;
  readonly layer: LiveLayer | null;
  readonly axis: number;
  /** Contexa held the response while deciding (synchronous). */
  readonly held: boolean;
  readonly verdict: string | null;
}

/** One approach's answer on the time axis, with its recorded time and what it let out. */
export function Bar({ control, layer, axis, held, verdict }: BarProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const width = layer ? Math.max(2, Math.round((layer.elapsedMs / axis) * 100)) : 0;
  const label = !layer
    ? t('e1.run.waiting')
    : control === 'D' && verdict
      ? t('e1.run.decided', {
          seconds: seconds(layer.elapsedMs),
          verdict: t(verdictKey(verdict)),
        })
      : layer.outcome === 'DELIVERED'
        ? t('e1.run.out', { seconds: seconds(layer.elapsedMs), items: count(layer.deliveredItems, language) })
        : control === 'D'
          ? // Contexa's answer is its decision; until the decision block arrives it is not called a denial.
            t('e1.run.decisionLoading', { seconds: seconds(layer.elapsedMs) })
          : t('e1.run.denied', { seconds: seconds(layer.elapsedMs) });
  return (
    <li className={styles.bar} data-control={control}>
      <span className={styles.barName}>{t(`control.${control}.name`)}</span>
      <span className={styles.barTrack}>
        <span
          className={styles.barFill}
          data-outcome={layer?.outcome ?? 'PENDING'}
          data-held={held || undefined}
          style={{ width: `${width}%` }}
        />
      </span>
      <span className={styles.barLabel}>{label}</span>
    </li>
  );
}
