import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { utcTime } from '../../journey/format';
import styles from './DecisionDetail.module.css';

/** What every tab receives: the request's anatomy and which run and request it is. */
export interface TabProps {
  readonly runId: string;
  readonly step: number;
}

/**
 * One tab of the decision details in the redesigned frame: its body, then its one source line (R-10). These are the
 * zones the automatic check measures inside the window; the window's own rows (requests, tabs) stay outside them.
 */
export function TabFrame({
  children,
  source = null,
}: {
  readonly children: ReactNode;
  readonly source?: ReactNode;
}) {
  return (
    <>
      <div className={styles.body} data-zone="body">
        {children}
      </div>
      {source ? (
        <p className={styles.source} data-zone="source">
          {source}
        </p>
      ) : null}
    </>
  );
}

/**
 * The record's own number, shown as it is (V-3: the record number is seen in the decision details), and when the
 * judgment was recorded, in UTC, when the server gives it.
 */
export function RecordNumber({ runId, at = null }: { readonly runId: string; readonly at?: string | null }) {
  const { t } = useTranslation();
  return (
    <>
      <span>{t('detail.r7.record.number')}</span>
      <code className={styles.original} data-original>
        {runId}
      </code>
      {at ? <span>{t('detail.r7.record.at', { time: utcTime(at) })}</span> : null}
    </>
  );
}
