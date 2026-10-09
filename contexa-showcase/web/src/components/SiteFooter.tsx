import { useTranslation } from 'react-i18next';
import { ActionChip } from './common/ActionChip';
import styles from './SiteFooter.module.css';

/** Small links on every visitor screen: the lab, adopting, the privacy notice and the benchmark. */
export function SiteFooter() {
  const { t } = useTranslation();
  return (
    <footer className={styles.footer}>
      <nav className={styles.links} aria-label={t('footer.label')}>
        <ActionChip to="/lab" icon="search" size="sm">
          {t('footer.lab')}
        </ActionChip>
        <ActionChip to="/adopt" icon="code" size="sm">
          {t('footer.adopt')}
        </ActionChip>
        <ActionChip to="/privacy" icon="lock" size="sm">
          {t('footer.privacy')}
        </ActionChip>
        <ActionChip to="/benchmark" icon="chart" size="sm">
          {t('footer.benchmark')}
        </ActionChip>
      </nav>
    </footer>
  );
}
