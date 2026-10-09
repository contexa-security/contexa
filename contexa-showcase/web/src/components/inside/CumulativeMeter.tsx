import { useTranslation } from 'react-i18next';
import type { Verdict } from '../../domain/verdict';
import { VerdictChip } from '../VerdictChip';
import styles from './CumulativeMeter.module.css';

export interface MeterRow {
  readonly request: number;
  /** The work profile observations the engine received; null when the engine did not analyse the request again. */
  readonly observations: number | null;
  /** The engine's CurrentVsObservedDeltaCount; null as above. */
  readonly deltas: number | null;
  readonly verdict: Verdict | null;
  readonly riskScore: number | null;
  /** Refused because a decision already in force applied (decision source PRIOR_DECISION). */
  readonly prior: boolean;
  /** Cells that changed from the row before, briefly highlighted. */
  readonly changed?: readonly ('observations' | 'deltas' | 'verdict')[];
}

interface CumulativeMeterProps {
  readonly caption: string;
  readonly rows: readonly MeterRow[];
  /** The sentence under the table, from the run's values. */
  readonly footnote?: string;
  /** Pinned to the top while the requests are still arriving (lab runs); a finished run's meter stays in place. */
  readonly pinned?: boolean;
}

/**
 * The cumulative meter (meter slide): pinned above a run of several requests, one row per request with what the engine
 * saw, how many items differed from usual and the decision. "—" means the engine did not analyse the request again,
 * and the reason is written next to it.
 */
export function CumulativeMeter({ caption, rows, footnote, pinned = true }: CumulativeMeterProps) {
  const { t } = useTranslation();
  return (
    <figure className={styles.meter} data-pinned={pinned || undefined}>
      <table className={styles.table}>
        <caption className={styles.caption}>{caption}</caption>
        <thead>
          <tr>
            <th scope="col">{t('meter.request')}</th>
            <th scope="col">{t('meter.observations')}</th>
            <th scope="col">{t('meter.deltas')}</th>
            <th scope="col">{t('meter.decision')}</th>
            <th scope="col">{t('meter.risk')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const changed = new Set(row.changed ?? []);
            return (
              <tr key={row.request}>
                <th scope="row" data-label={t('meter.request')}>
                  {row.request}
                </th>
                <td
                  data-label={t('meter.observations')}
                  data-changed={changed.has('observations') || undefined}
                >
                  {row.observations === null ? t('meter.none') : row.observations}
                </td>
                <td data-label={t('meter.deltas')} data-changed={changed.has('deltas') || undefined}>
                  {row.deltas === null ? t('meter.none') : row.deltas}
                </td>
                <td data-label={t('meter.decision')} data-changed={changed.has('verdict') || undefined}>
                  {row.prior ? (
                    t('meter.prior')
                  ) : row.verdict ? (
                    <VerdictChip verdict={row.verdict} />
                  ) : (
                    t('meter.none')
                  )}
                </td>
                <td data-label={t('meter.risk')}>
                  {row.verdict === null ? t('meter.none') : (row.riskScore ?? t('meter.noValue'))}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <figcaption className={styles.footnote}>
        {footnote ? <span>{footnote} </span> : null}
        {rows.some((row) => row.observations === null) ? <span>{t('meter.why')}</span> : null}
      </figcaption>
    </figure>
  );
}
