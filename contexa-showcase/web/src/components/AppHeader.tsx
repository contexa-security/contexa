import { useTranslation } from 'react-i18next';
import { SUPPORTED_LANGUAGES } from '../i18n';
import styles from './AppHeader.module.css';

/** Brand bar with the language switch; the experience never asks the visitor for anything else. */
export function AppHeader() {
  const { t, i18n } = useTranslation();
  return (
    <header className={styles.bar}>
      <a className={styles.brand} href="/">
        CONTEXA <span className={styles.brandDemo}>DEMO</span>
      </a>
      <div className={styles.languages} role="group" aria-label={t('app.language')}>
        {SUPPORTED_LANGUAGES.map((language) => (
          <button
            key={language}
            type="button"
            className={styles.language}
            aria-pressed={i18n.language === language}
            lang={language}
            onClick={() => void i18n.changeLanguage(language)}
          >
            {t(`app.language.${language}`)}
          </button>
        ))}
      </div>
    </header>
  );
}
