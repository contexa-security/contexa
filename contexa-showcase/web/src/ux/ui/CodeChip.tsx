import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Icon } from './Icon';
import styles from './CodeChip.module.css';
import { breakable } from './breakable';

interface CodeChipProps {
  /** A run ID, a hash, a scenario code: shown in the fixed-width face, whole. */
  readonly value: string;
  /** Pressing it copies the value (기획안 5.2 코드 칩). */
  readonly copy?: boolean;
}

export function CodeChip({ value, copy = false }: CodeChipProps) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) {
      return undefined;
    }
    const timer = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(timer);
  }, [copied]);
  if (!copy) {
    return <code className={styles.chip}>{breakable(value)}</code>;
  }
  return (
    <span className={styles.wrap}>
      <button
        type="button"
        className={styles.chip}
        aria-label={t('ux.code.copy', { value })}
        onClick={() => {
          // A browser without the clipboard (an insecure page) leaves the value as selectable text.
          void navigator.clipboard?.writeText(value).then(
            () => setCopied(true),
            () => setCopied(false),
          );
        }}
      >
        <code>{breakable(value)}</code>
        <Icon name={copied ? 'copy-check' : 'copy'} size="xs" />
      </button>
      <span role="status" className={copied ? styles.copied : 'ux-sr-only'}>
        {copied ? t('ux.code.copied') : ''}
      </span>
    </span>
  );
}
