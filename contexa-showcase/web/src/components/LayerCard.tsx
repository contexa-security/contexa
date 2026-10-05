import { useTranslation } from 'react-i18next';
import type { BusinessOutcome, ControlId, Verdict } from '../domain/verdict';
import { OUTCOME_KEYS } from '../domain/verdict';
import { VerdictChip } from './VerdictChip';
import styles from './LayerCard.module.css';

interface LayerCardProps {
  readonly control: ControlId;
  readonly outcome: BusinessOutcome;
  readonly verdict: Verdict;
  /** Short, localized reason shown under the verdict. */
  readonly reason: string;
  /** Contexa is the subject of the demo and is visually emphasized. */
  readonly highlighted?: boolean;
  /**
   * When the parent lays cards out on a shared row grid (CSS subgrid), the five parts of every card
   * line up across cards even if one card's text wraps to more lines.
   */
  readonly rowAligned?: boolean;
  readonly onOpenEvidence: (control: ControlId) => void;
}

/** One security layer's result: business outcome first, verdict second, reason third. */
export function LayerCard({
  control,
  outcome,
  verdict,
  reason,
  highlighted = false,
  rowAligned = false,
  onOpenEvidence,
}: LayerCardProps) {
  const { t } = useTranslation();
  const titleId = `layer-${control}-title`;
  return (
    <article
      className={styles.card}
      data-highlighted={highlighted}
      data-aligned={rowAligned}
      data-control={control}
      aria-labelledby={titleId}
    >
      <header className={styles.header}>
        <span className={styles.layer} aria-hidden="true">
          {control}
        </span>
        <div className={styles.identity}>
          <h3 id={titleId} className={styles.name}>
            {t(`control.${control}.name`)}
          </h3>
          <p className={styles.config}>{t(`control.${control}.config`)}</p>
        </div>
      </header>
      <p className={styles.outcome} data-outcome={outcome}>
        {t(OUTCOME_KEYS[outcome])}
      </p>
      <div className={styles.verdict}>
        <VerdictChip verdict={verdict} />
      </div>
      <p className={styles.reason}>{reason}</p>
      <button type="button" className={styles.evidence} onClick={() => onOpenEvidence(control)}>
        {t('evidence.open')}
        <span className={styles.visuallyHidden}>{` — ${t(`control.${control}.name`)}`}</span>
      </button>
    </article>
  );
}
