import { Suspense, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Outlet, useLocation } from 'react-router-dom';
import { useVisitor } from '../../api/queries';
import { formatNumber } from '../format';
import { groupOf, menuItemOf } from '../routes';
import { useRunLog } from '../runs/runLog';
import { Drawer, Icon, Loading, type Crumb } from '../ui';
import { DRAWER_QUERY, RAIL_QUERY, useMedia } from '../useMedia';
import { CrumbProvider } from './crumbs';
import { useExtraCrumbs } from './crumbState';
import { RouteFocus } from './RouteFocus';
import { SearchDialog } from './SearchDialog';
import { Brand, SideNav } from './SideNav';
import { TopBar } from './TopBar';
import styles from './Shell.module.css';

/**
 * The frame of every screen (기획안 5.1): the side menu (248), the top bar (56) and the content (at most 1320 wide).
 * A threat simulation runs in focus mode: the menu folds to the 72 icon rail and the content centres at 1120. From 1024
 * to 1279 the menu is the rail; below 1024 it opens as a drawer from the top bar's menu button.
 */
function Frame() {
  const { t, i18n } = useTranslation();
  const { pathname } = useLocation();
  // The visitor is known on every screen, as the old header made it: the portal writes the visitor cookie and the
  // CSRF token every write needs with that answer, whichever screen a visitor opens first.
  useVisitor();
  // The decision log's count beside its menu item: the rows the log shows (DEC-16, DEC-40).
  const log = useRunLog();
  const counts = log.pending ? {} : { runs: formatNumber(log.rows.length, i18n.language) };
  const item = menuItemOf(pathname);
  const group = item ? groupOf(item) : null;
  const extra = useExtraCrumbs();
  const medium = useMedia(RAIL_QUERY);
  const narrow = useMedia(DRAWER_QUERY);
  const [drawer, setDrawer] = useState(false);
  const [search, setSearch] = useState(false);
  // A new key for each opening gives the search a fresh, empty dialog.
  const [searchKey, setSearchKey] = useState(0);
  const openSearch = () => {
    setSearchKey((key) => key + 1);
    setSearch(true);
  };
  const focus = item?.focus === true;
  const rail = !narrow && (focus || medium);

  useEffect(() => {
    const open = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setSearchKey((key) => key + 1);
        setSearch(true);
      }
    };
    window.addEventListener('keydown', open);
    return () => window.removeEventListener('keydown', open);
  }, []);

  const crumbs: Crumb[] = [
    ...(group ? [{ label: t(`ux.nav.group.${group.id}`) }] : []),
    ...(item ? [{ label: t(`ux.menu.${item.id}`), ...(extra.length > 0 ? { to: item.path } : {}) }] : []),
    ...extra,
  ];

  return (
    <div
      className={styles.app}
      data-rail={rail || undefined}
      data-drawer={narrow || undefined}
      data-focus={focus || undefined}
    >
      <a className={styles.skip} href="#main">
        {t('ux.skip')}
      </a>
      {narrow ? null : (
        <aside className={styles.side}>
          <Brand />
          <SideNav current={item} counts={counts} />
        </aside>
      )}
      <TopBar crumbs={crumbs} onMenu={() => setDrawer(true)} menuOpen={drawer} onSearch={openSearch} />
      <main id="main" className={styles.content}>
        <div className={styles.wrap}>
          <Suspense fallback={<Loading rows={4} />}>
            <Outlet />
          </Suspense>
        </div>
      </main>
      <Drawer open={drawer && narrow} side="start" title={<Brand inline />} onClose={() => setDrawer(false)}>
        <button
          type="button"
          className={styles.drawerSearch}
          onClick={() => {
            setDrawer(false);
            openSearch();
          }}
        >
          <Icon name="search" size="md" />
          {t('ux.top.search')}
        </button>
        <SideNav current={item} counts={counts} onNavigate={() => setDrawer(false)} />
      </Drawer>
      <SearchDialog key={searchKey} open={search} onClose={() => setSearch(false)} />
      <RouteFocus />
    </div>
  );
}

export function Shell() {
  return (
    <CrumbProvider>
      <Frame />
    </CrumbProvider>
  );
}
