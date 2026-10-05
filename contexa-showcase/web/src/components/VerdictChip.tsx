import { useTranslation } from 'react-i18next';
import { VERDICTS, type Verdict } from '../domain/verdict';
import { Icon } from './Icon';
import styles from './VerdictChip.module.css';

interface VerdictChipProps {
  readonly verdict: Verdict;
  /** Shows the standard engine code (ALLOW, BLOCK...) next to the plain word. */
  readonly showCode?: boolean;
  /**
   * The engine gave no decision for a finished request (a technical failure such as a model rate limit). The server
   * sends such a result as PENDING so it never reads as a verdict; the chip then says "unresolved", because nothing is
   * still being analysed.
   */
  readonly unresolved?: boolean;
}

/** Color, icon and word together, so the verdict never depends on color alone. */
export function VerdictChip({ verdict, showCode = false, unresolved = false }: VerdictChipProps) {
  const { t } = useTranslation();
  const presentation = VERDICTS[verdict];
  return (
    <span className={styles.chip} data-verdict={verdict} data-unresolved={unresolved || undefined}>
      <Icon name={presentation.icon} className={styles.icon} />
      <span>{t(unresolved ? 'verdict.unresolved' : presentation.labelKey)}</span>
      {showCode ? (
        <span className={styles.code}>{unresolved ? 'NO_DECISION' : presentation.code}</span>
      ) : null}
    </span>
  );
}
