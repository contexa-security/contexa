import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import styles from './SiteFooter.module.css';

/** Small links on every visitor screen: the library, adopting, the privacy notice and the statistics. */
export function SiteFooter() {
  const { t } = useTranslation();
  return (
    <footer className={styles.footer}>
      <nav className={styles.links} aria-label={t('footer.label')}>
        <Link to="/library">{t('footer.library')}</Link>
        <Link to="/adopt">{t('footer.adopt')}</Link>
        <Link to="/privacy">{t('footer.privacy')}</Link>
        <Link to="/stats">{t('footer.stats')}</Link>
      </nav>
    </footer>
  );
}
