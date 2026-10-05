import { useTranslation } from 'react-i18next';
import { VERDICTS, type Verdict } from '../domain/verdict';
import { Icon } from './Icon';
import styles from './VerdictChip.module.css';

interface VerdictChipProps {
  readonly verdict: Verdict;
  /** Shows the standard engine code (ALLOW, BLOCK...) next to the plain word. */
  readonly showCode?: boolean;
}

/** Color, icon and word together, so the verdict never depends on color alone. */
export function VerdictChip({ verdict, showCode = false }: VerdictChipProps) {
  const { t } = useTranslation();
  const presentation = VERDICTS[verdict];
  return (
    <span className={styles.chip} data-verdict={verdict}>
      <Icon name={presentation.icon} className={styles.icon} />
      <span>{t(presentation.labelKey)}</span>
      {showCode ? <span className={styles.code}>{presentation.code}</span> : null}
    </span>
  );
}
