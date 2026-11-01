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
        {MENU.map((group) => (
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
      to="/"
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
