import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import styles from './Facts.module.css';

interface OriginalChipProps {
  /** The engine's own text, shown as it is once the chip is pressed (C-5's allowed exception, D-29). */
  readonly text: string;
}

/**
 * The "original" chip of a value given in plain words (N-DEP-1, C-5): pressed, it opens the engine's own
 * text in place, marked as the original, as the fact card opens its line.
 */
export function OriginalChip({ text }: OriginalChipProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const boxId = useId();
  return (
    <>
      <button
        type="button"
        className={styles.originalChip}
        aria-expanded={open}
        aria-controls={boxId}
        onClick={() => setOpen((value) => !value)}
      >
        {t('source.original')}
      </button>
      {open ? (
        <code id={boxId} className={styles.factLine} data-original>
          {text}
        </code>
      ) : null}
    </>
  );
}
