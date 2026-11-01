import { useTranslation } from 'react-i18next';
import { useLiveConfig, useStats } from '../../api/queries';
import { setLanguage } from '../../i18n';
import { formatNumber } from '../format';
import { useTheme } from '../theme';
import { Breadcrumbs, Icon, type Crumb } from '../ui';
import styles from './Shell.module.css';

interface TopBarProps {
  readonly crumbs: readonly Crumb[];
  /** Opens the menu drawer (narrow screens). */
  readonly onMenu: () => void;
  readonly menuOpen: boolean;
  readonly onSearch: () => void;
}

/** Whether visitors can send real runs now: on, paused for the day, or not offered by this portal. */
function LivePill() {
  const { t } = useTranslation();
  const live = useLiveConfig();
  const state = live.data ? (live.data.paused ? 'paused' : 'on') : live.isError ? 'off' : null;
  if (!state) {
    return null;
  }
  return (
    <span className={styles.pill} data-state={state}>
      <span className={styles.dot} aria-hidden="true" />
      {t(`ux.top.live.${state}`)}
    </span>
  );
}

/** Today's visitor runs and every decision so far, as the portal counts them (/api/stats). */
function CountsPill() {
  const { t, i18n } = useTranslation();
  const stats = useStats();
  if (!stats.data) {
    return null;
  }
  const decisions = stats.data.engineDecisions ?? stats.data.decisionTime.decisions;
  return (
    <span className={[styles.pill, styles.wideOnly].join(' ')}>
      {t('ux.top.today')} <b>{formatNumber(stats.data.runs.today, i18n.language)}</b>{' '}
      <span className={styles.pillSep} aria-hidden="true">
        ·
      </span>{' '}
      {t('ux.top.total')} <b>{formatNumber(decisions, i18n.language)}</b>
    </span>
  );
}

/**
 * The top bar (기획안 4.2, 56 high): the breadcrumb, the search, the two status pills, the language and the theme. On a
 * phone it keeps the menu, the logo and the language.
 */
export function TopBar({ crumbs, onMenu, menuOpen, onSearch }: TopBarProps) {
  const { t, i18n } = useTranslation();
  const { theme, toggle } = useTheme();
  const other = i18n.language === 'ko' ? 'en' : 'ko';
  return (
    <header className={styles.top}>
      <button
        type="button"
        className={[styles.iconButton, styles.menuButton].join(' ')}
        aria-label={t('ux.top.menu')}
        aria-expanded={menuOpen}
        onClick={onMenu}
      >
        <Icon name="menu" />
      </button>
      <span className={[styles.brandMark, styles.drawerMark].join(' ')} aria-hidden="true">
        C
      </span>
      <div className={styles.crumbArea}>
        <Breadcrumbs items={crumbs} />
      </div>
      <div className={styles.topRight}>
        <button
          type="button"
          className={styles.searchButton}
          onClick={onSearch}
          aria-label={t('ux.top.search')}
          aria-keyshortcuts="Control+K Meta+K"
        >
          <Icon name="search" size="md" />
          <span className={styles.searchText}>{t('ux.top.search')}</span>
          <kbd className={styles.kbd}>Ctrl K</kbd>
        </button>
        <span className={styles.pills}>
          <LivePill />
          <CountsPill />
        </span>
        <button
          type="button"
          className={[styles.iconButton, styles.langButton].join(' ')}
          aria-label={t('ux.top.language', { other: other === 'en' ? 'English' : '한국어' })}
          onClick={() => void setLanguage(other)}
        >
          <Icon name="globe" size="md" />
          <span aria-hidden="true">{i18n.language === 'ko' ? 'KO' : 'EN'}</span>
        </button>
        <button
          type="button"
          className={[styles.iconButton, styles.themeButton].join(' ')}
          aria-label={t(theme === 'dark' ? 'ux.top.theme.toLight' : 'ux.top.theme.toDark')}
          onClick={toggle}
        >
          <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
        </button>
      </div>
    </header>
  );
}
