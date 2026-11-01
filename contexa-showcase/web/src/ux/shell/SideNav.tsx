import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { FOOT, MENU, type MenuItem } from '../routes';
import { Icon } from '../ui';
import styles from './Shell.module.css';

interface SideNavProps {
  /** The item of the screen on view; it carries the gold stripe and aria-current. */
  readonly current: MenuItem | null;
  /** A count after an item's name (the decision log's records), when the screen knows it. */
  readonly counts?: Partial<Record<MenuItem['id'], string>>;
  /** Pressing an item (the drawer closes on it). */
  readonly onNavigate?: () => void;
}

function NavLink({
  item,
  current,
  count,
  onNavigate,
}: {
  readonly item: MenuItem;
  readonly current: boolean;
  readonly count: string | undefined;
  readonly onNavigate: (() => void) | undefined;
}) {
  const { t } = useTranslation();
  const label = t(`ux.menu.${item.id}`);
  return (
    <Link
      to={item.path}
      className={styles.navItem}
      aria-current={current ? 'page' : undefined}
      title={label}
      onClick={onNavigate}
    >
      <Icon name={item.icon} className={styles.navIcon} />
      <span className={styles.navLabel}>{label}</span>
      {count ? (
        <span className={styles.navCount} aria-hidden="true">
          {count}
        </span>
      ) : null}
    </Link>
  );
}

/** The menus where the demo is run (DEC-77): the start of the demo and the threat simulations. */
const LIVE_GROUPS: ReadonlySet<string> = new Set(['live', 'simulate']);

/**
 * A live-demo menu item (DEC-77): a larger name with its icon in a tile and one line of what it runs. The link is named
 * by the menu's name alone; the line describes it.
 */
function LiveNavLink({
  item,
  current,
  onNavigate,
}: {
  readonly item: MenuItem;
  readonly current: boolean;
  readonly onNavigate: (() => void) | undefined;
}) {
  const { t } = useTranslation();
  const descId = useId();
  const label = t(`ux.menu.${item.id}`);
  return (
    <Link
      to={item.path}
      className={styles.liveItem}
      aria-current={current ? 'page' : undefined}
      aria-label={label}
      aria-describedby={descId}
      title={label}
      onClick={onNavigate}
    >
      <span className={styles.liveIcon}>
        <Icon name={item.icon} size="lg" />
      </span>
      <span className={styles.liveText}>
        <span className={styles.liveLabel}>{label}</span>
        <span id={descId} className={styles.liveDesc}>
          {t(`ux.nav.desc.${item.id}`)}
        </span>
      </span>
    </Link>
  );
}

/**
 * The live-demo panel at the top of the menu (DEC-77): a live dot and "real decision engine", then the start of the
 * demo and the threat simulations as large items, the simulations under their own small heading.
 */
function LivePanel({
  current,
  onNavigate,
}: {
  readonly current: MenuItem | null;
  readonly onNavigate: (() => void) | undefined;
}) {
  const { t } = useTranslation();
  const titleId = useId();
  return (
    <section className={styles.livePanel} aria-labelledby={titleId}>
      <p className={styles.liveHead}>
        <span className={styles.liveDot} aria-hidden="true" />
        <span id={titleId} className={styles.liveTitle}>
          {t('ux.nav.group.live')}
        </span>
        <span className={styles.liveTag}>{t('ux.nav.live.engine')}</span>
      </p>
      {MENU.filter((group) => LIVE_GROUPS.has(group.id)).map((group) => (
        <div key={group.id} className={styles.liveGroup}>
          {group.id === 'live' ? null : <p className={styles.liveGroupTitle}>{t(`ux.nav.group.${group.id}`)}</p>}
          <ul className={styles.liveList}>
            {group.items.map((item) => (
              <li key={item.id}>
                <LiveNavLink item={item} current={current?.id === item.id} onNavigate={onNavigate} />
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}

/**
 * The menu in the order a visitor walks (기획안 4절): the live demo, the threat simulations, the results, the
 * validation, adoption and operations, and the glossary and privacy at its foot. The same list fills the side menu, the
 * icon rail and the drawer; the rail keeps the names for assistive technology and shows them on hover.
 */
export function SideNav({ current, counts = {}, onNavigate }: SideNavProps) {
  const { t } = useTranslation();
  return (
    <nav aria-label={t('ux.nav.label')} className={styles.nav}>
      <div className={styles.navGroups}>
        <LivePanel current={current} onNavigate={onNavigate} />
        {MENU.filter((group) => !LIVE_GROUPS.has(group.id)).map((group) => (
          <div key={group.id} className={styles.navGroup}>
            <p className={styles.navGroupTitle}>{t(`ux.nav.group.${group.id}`)}</p>
            <ul className={styles.navList}>
              {group.items.map((item) => (
                <li key={item.id}>
                  <NavLink
                    item={item}
                    current={current?.id === item.id}
                    count={counts[item.id]}
                    onNavigate={onNavigate}
                  />
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <ul className={[styles.navList, styles.navFoot].join(' ')}>
        {FOOT.map((item) => (
          <li key={item.id}>
            <NavLink
              item={item}
              current={current?.id === item.id}
              count={counts[item.id]}
              onNavigate={onNavigate}
            />
          </li>
        ))}
      </ul>
    </nav>
  );
}

/**
 * The logo: the gold mark, the name and the "live demo" tag; the tag and the name fold away on the rail. Inline, it sits
 * in the drawer's head without the side menu's height and line.
 */
export function Brand({ inline = false }: { readonly inline?: boolean }) {
  const { t } = useTranslation();
  return (
    <Link
      to="/start"
      className={[styles.brand, inline ? styles.brandInline : ''].filter(Boolean).join(' ')}
      aria-label={`Contexa · ${t('ux.brand.tag')}`}
    >
      <span className={styles.brandMark} aria-hidden="true">
        C
      </span>
      <span className={styles.brandName}>Contexa</span>
      <span className={styles.brandTag}>{t('ux.brand.tag')}</span>
    </Link>
  );
}
