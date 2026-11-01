import { Fragment, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Icon } from './Icon';
import styles from './PageHead.module.css';

interface PageHeadProps {
  /** The category line above the title: badges 22 and code chips 24, 8 apart. */
  readonly kicker?: ReactNode;
  readonly title: string;
  /** A state badge next to the title (a run's verdict, a benchmark's status). */
  readonly status?: ReactNode;
  /** One or two plain sentences on what the screen does and which data it reads (W-2). */
  readonly desc?: ReactNode;
  /** At most two actions; one of them at most is the gold primary action. */
  readonly actions?: ReactNode;
}

/**
 * The page head (기획안 5.2): kicker → 6 → title 28/700 (24 on a phone) → 8 → description 15 (at most 760 wide). The
 * title is the screen's only h1; the application moves the focus to it when a new screen opens.
 */
export function PageHead({ kicker, title, status, desc, actions }: PageHeadProps) {
  return (
    <header className={styles.head}>
      <div className={styles.main}>
        {kicker ? <div className={styles.kicker}>{kicker}</div> : null}
        <div className={styles.titleRow}>
          <h1 tabIndex={-1} className={styles.title}>
            {title}
          </h1>
          {status}
        </div>
        {desc ? <p className={styles.desc}>{desc}</p> : null}
      </div>
      {actions ? <div className={styles.actions}>{actions}</div> : null}
    </header>
  );
}

export interface SummaryItem {
  readonly label: ReactNode;
  readonly value: ReactNode;
}

/** A row of name (13) and value (15/600) cells with lines between (판정 상세 · 표준 벤치마크 머리). */
export function SummaryBar({
  items,
  label,
}: {
  readonly items: readonly SummaryItem[];
  readonly label?: string;
}) {
  return (
    <dl className={styles.summary} aria-label={label}>
      {items.map((item, index) => (
        <div key={index} className={styles.summaryCell}>
          <dt className={styles.summaryLabel}>{item.label}</dt>
          <dd className={styles.summaryValue}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export interface Crumb {
  readonly label: string;
  readonly to?: string;
}

/** Where the screen sits in the menu; the last place is the current page. One line that shortens on narrow bars. */
export function Breadcrumbs({ items }: { readonly items: readonly Crumb[] }) {
  const { t } = useTranslation();
  return (
    <nav aria-label={t('ux.crumbs.label')} className={styles.crumbs}>
      <ol className={styles.crumbList}>
        {items.map((item, index) => {
          const last = index === items.length - 1;
          return (
            <Fragment key={`${index}-${item.label}`}>
              {index > 0 ? (
                <li aria-hidden="true" className={styles.crumbSep}>
                  <Icon name="chevron-right" size="sm" />
                </li>
              ) : null}
              <li className={last ? styles.crumbNow : styles.crumb}>
                {last || !item.to ? (
                  <span aria-current={last ? 'page' : undefined}>{item.label}</span>
                ) : (
                  <Link to={item.to}>{item.label}</Link>
                )}
              </li>
            </Fragment>
          );
        })}
      </ol>
    </nav>
  );
}
