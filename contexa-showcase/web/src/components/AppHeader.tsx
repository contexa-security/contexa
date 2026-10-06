import { useTranslation } from 'react-i18next';
import { NavLink } from 'react-router-dom';
import { SUPPORTED_LANGUAGES } from '../i18n';
import styles from './AppHeader.module.css';

/** Where a visitor can go from every screen, named by what they will do there. */
const NAV = [
  { to: '/', key: 'nav.start', end: true },
  { to: '/library', key: 'nav.library', end: false },
  { to: '/stats', key: 'nav.stats', end: false },
  { to: '/adopt', key: 'nav.adopt', end: false },
] as const;

/** Brand bar with the demo menu and the language switch; the experience never asks the visitor for anything else. */
export function AppHeader() {
  const { t, i18n } = useTranslation();
  return (
    <header className={styles.bar}>
      <a className={styles.brand} href="/">
        CONTEXA <span className={styles.brandDemo}>DEMO</span>
      </a>
      <nav className={styles.nav} aria-label={t('nav.label')}>
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) => (isActive ? `${styles.navLink} ${styles.navActive}` : styles.navLink)}
          >
            {t(item.key)}
          </NavLink>
        ))}
      </nav>
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
