import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { NavLink, useLocation } from 'react-router-dom';
import { setLanguage, SUPPORTED_LANGUAGES } from '../i18n';
import { useJourneyPlace } from '../journey/useJourneyPlace';
import { useGlossary } from './common/glossaryTerms';
import { IdentityLine } from './journey/JourneyParts';
import styles from './AppHeader.module.css';

/**
 * Where a visitor can go from every screen, named by what they will do there (common-1): try it yourself, concepts
 * first, the lab, the benchmark and adopting it; the glossary and the language follow.
 */
const NAV = [
  { to: '/', key: 'nav.try', end: true },
  { to: '/intro', key: 'nav.intro', end: false },
  { to: '/lab', key: 'nav.lab', end: false },
  { to: '/benchmark', key: 'nav.benchmark', end: false },
  { to: '/adopt', key: 'nav.adopt', end: false },
] as const;

/**
 * Brand bar with the demo menu, the glossary and the language switch, and the identity line under it on every screen
 * (thread); the experience never asks the visitor for anything else.
 */
export function AppHeader() {
  const { t, i18n } = useTranslation();
  const openGlossary = useGlossary();
  const place = useJourneyPlace();
  const { pathname } = useLocation();
  const navRef = useRef<HTMLElement>(null);
  // A screen of a route belongs to the menu item of the route it is seen on (the place band's own rule, D-33): the
  // concept path to "concepts first", the default route to "try it yourself"; any other screen to its own item. The
  // lab, the benchmark and adopting are their own items even where the concept path lists them as its last step.
  const ownItem = NAV.some(
    (item) =>
      !item.end && item.to !== '/intro' && (pathname === item.to || pathname.startsWith(`${item.to}/`)),
  );
  const onRoute = place.screen !== null && !ownItem;
  const active = (to: string, isActive: boolean) =>
    to === '/'
      ? onRoute && place.route === 'DEFAULT'
      : to === '/intro'
        ? onRoute && place.route === 'INTRO'
        : isActive;
  // On phones the menu is one row that slides sideways (its height never depends on how wide the font draws the
  // words); the current item is slid into view.
  useEffect(() => {
    const nav = navRef.current;
    const current = nav?.querySelector<HTMLElement>(`.${styles.navActive}`);
    if (!nav || !current || nav.scrollWidth <= nav.clientWidth) {
      return;
    }
    nav.scrollLeft = current.offsetLeft - nav.offsetLeft - (nav.clientWidth - current.offsetWidth) / 2;
  });
  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <header className={styles.bar}>
        <a className={styles.brand} href="/">
          CONTEXA <span className={styles.brandDemo}>DEMO</span>
        </a>
        <nav ref={navRef} className={styles.nav} aria-label={t('nav.label')}>
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                active(item.to, isActive) ? `${styles.navLink} ${styles.navActive}` : styles.navLink
              }
            >
              {t(item.key)}
            </NavLink>
          ))}
        </nav>
        <button type="button" className={styles.glossary} onClick={() => openGlossary()}>
          {t('glossary.open')}
        </button>
        <div className={styles.languages} role="group" aria-label={t('app.language')}>
          {SUPPORTED_LANGUAGES.map((language) => (
            <button
              key={language}
              type="button"
              className={styles.language}
              aria-pressed={i18n.language === language}
              lang={language}
              onClick={() => void setLanguage(language)}
            >
              {t(`app.language.${language}`)}
            </button>
          ))}
        </div>
      </header>
      <IdentityLine />
    </>
  );
}
