import { useTranslation } from 'react-i18next';
import type { FactSource } from '../../api/promptQuality';
import styles from './Facts.module.css';

/**
 * Where a fact came from (U-1, source chip): company record, learned, computed, inferred or outside text, the v20
 * dictionary's five source grades. The kinds share one look and are told apart by their words, never by a colour; a
 * line that states no grade says so.
 */
export function SourceChip({ source }: { readonly source: FactSource | null }) {
  const { t } = useTranslation();
  const kind = source ?? 'NONE';
  return (
    <span className={styles.sourceChip} data-source={kind}>
      <span className="visually-hidden">{`${t('fact.source.title')} `}</span>
      <span>{t(`fact.source.${kind}`)}</span>
    </span>
  );
}
