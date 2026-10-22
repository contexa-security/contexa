import { useTranslation } from 'react-i18next';
import { THEMES, type Theme } from './themes';
import styles from './ThemePair.module.css';

/**
 * The two themes side by side (IN-6: one card on the map and on both themes' covers): the stolen account, where only
 * the account is real and the device or the behaviour is strange, and the insider, where the account, the rights, the
 * assignment and the records are all real. The theme of the screen it stands on is marked as the one shown, and the
 * other is faint, so neither reads as a button to press (B-12).
 */
export function ThemePair({ current = null }: { readonly current?: Theme | null }) {
  const { t } = useTranslation();
  return (
    <section className={styles.pair} aria-label={t('theme.title')} data-block>
      {THEMES.map((theme) => (
        <div
          key={theme.id}
          className={styles.theme}
          data-current={current === theme.id || undefined}
          data-other={(current !== null && current !== theme.id) || undefined}
        >
          {current === theme.id ? <span className={styles.current}>{t('theme.current')}</span> : null}
          <b className={styles.name}>{t(`theme.${theme.id}.name`)}</b>
          <span className={styles.line}>{t(`theme.${theme.id}.line`)}</span>
        </div>
      ))}
    </section>
  );
}
