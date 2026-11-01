import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { ControlId, Verdict } from '../../domain/verdict';
import { formatDuration, formatNumber } from '../format';
import { Badge, VerdictBadge } from '../ui';
import { CONTROL_TONE } from './controls';
import styles from './Simulate.module.css';

export interface LaneRow {
  readonly control: ControlId;
  /** The decision the answer amounts to (person.ts controlVerdict); null while the answer has not come. */
  readonly verdict: Verdict | 'PRIOR' | null;
  /** Items the control handed over; null while unknown. */
  readonly items: number | null;
  /** Milliseconds from the request to the control's response; null while unknown. */
  readonly ms: number | null;
  /** What the control looked at, under its name. */
  readonly sub?: ReactNode;
  /** Shown in the time column while the answer is still coming (Contexa deciding). */
  readonly pending?: ReactNode;
}

/**
 * The five security controls' answers to the same request, one row each: the control, its decision, the items it
 * handed over and its response time (기획안 7.0 d-home · d-live). Contexa's row comes last and carries the gold mark.
 */
export function ControlLanes({ rows, label }: { readonly rows: readonly LaneRow[]; readonly label: string }) {
  const { t, i18n } = useTranslation();
  return (
    <table className={styles.lanes}>
      <caption className="ux-sr-only">{label}</caption>
      <thead className="ux-sr-only">
        <tr>
          <th scope="col">{t('ux.lanes.control')}</th>
          <th scope="col">{t('ux.lanes.decision')}</th>
          <th scope="col">{t('ux.lanes.items')}</th>
          <th scope="col">{t('ux.lanes.time')}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.control} className={styles.lane} data-contexa={row.control === 'D' || undefined}>
            <th scope="row" className={styles.laneName}>
              <span className={styles.swatch} data-tone={CONTROL_TONE[row.control]} aria-hidden="true" />
              <span>
                {t(`ux.control.${row.control}`)}
                {row.sub ? <small className={styles.laneSub}>{row.sub}</small> : null}
              </span>
            </th>
            <td className={styles.laneVerdict}>
              {row.verdict === 'PRIOR' ? (
                <Badge tone="none" icon="minus">
                  {t('ux.lanes.prior')}
                </Badge>
              ) : row.verdict ? (
                <VerdictBadge verdict={row.verdict} />
              ) : (
                <span className={styles.laneWait}>…</span>
              )}
            </td>
            <td className={styles.laneItems}>
              {row.items === null
                ? '…'
                : t('ux.facts.items', { count: row.items, n: formatNumber(row.items, i18n.language) })}
            </td>
            <td className={styles.laneTime}>
              {row.ms !== null
                ? t('ux.time.seconds', { value: formatDuration(row.ms, i18n.language) })
                : (row.pending ?? '—')}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
