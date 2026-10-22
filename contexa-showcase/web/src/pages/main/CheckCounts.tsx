import { Trans } from 'react-i18next';
import styles from './CheckCounts.module.css';

/**
 * One check of the engine inspector in 3-3's words (P-39): what matched in green, a mismatch in red and quiet when
 * there is none, and what could not be checked in grey, since it is neither a pass nor a failure (L-34).
 */
export function CheckCounts({
  matched,
  mismatched,
  unverifiable,
}: {
  readonly matched: number;
  readonly mismatched: number;
  readonly unverifiable: number;
}) {
  return (
    <b className={styles.counts}>
      <Trans
        i18nKey="main.3-3.checkCounts"
        values={{ matched, mismatched, unverifiable }}
        components={{
          ok: <span className={styles.part} data-tone="ok" />,
          bad: <span className={styles.part} data-tone={mismatched > 0 ? 'bad' : 'quiet'} />,
          unknown: <span className={styles.part} data-tone="unknown" />,
        }}
      />
    </b>
  );
}
