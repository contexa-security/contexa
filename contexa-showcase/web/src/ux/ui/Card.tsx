import { useId, type ReactNode } from 'react';
import { Icon, type UxIconName } from './Icon';
import styles from './Card.module.css';

interface CardProps {
  /** A titled card is a named region; its head holds the title (18/600), the line under it (13) and the actions. */
  readonly title?: ReactNode;
  readonly sub?: ReactNode;
  readonly actions?: ReactNode;
  readonly level?: 2 | 3;
  /** The body has no padding: a table or a list that runs to the card's edges. */
  readonly flush?: boolean;
  /** Contexa's own row of a comparison: the gold stripe on the left. */
  readonly highlight?: boolean;
  readonly className?: string;
  readonly children?: ReactNode;
}

export function Card({
  title,
  sub,
  actions,
  level = 2,
  flush = false,
  highlight = false,
  className,
  children,
}: CardProps) {
  const titleId = useId();
  const Heading = level === 2 ? 'h2' : 'h3';
  const classes = [styles.card, highlight ? styles.highlight : '', className].filter(Boolean).join(' ');
  if (title === undefined) {
    return <div className={[classes, flush ? '' : styles.padded].filter(Boolean).join(' ')}>{children}</div>;
  }
  return (
    <section className={classes} aria-labelledby={titleId}>
      <header className={styles.head}>
        <div className={styles.headText}>
          <Heading id={titleId} className={styles.title}>
            {title}
          </Heading>
          {sub ? <p className={styles.sub}>{sub}</p> : null}
        </div>
        {actions ? <div className={styles.actions}>{actions}</div> : null}
      </header>
      {children !== undefined ? <div className={flush ? undefined : styles.body}>{children}</div> : null}
    </section>
  );
}

interface KpiProps {
  readonly icon: UxIconName;
  readonly label: string;
  /** The figure, already written for the language (grouped thousands, fixed decimals). */
  readonly value: ReactNode;
  readonly unit?: string;
  /** The sample and the period, on the same card (W-6): never an empty line. */
  readonly foot?: ReactNode;
}

/** A figure card: icon chip 40, name 13/500, figure 32/700 fixed-width with a 15 unit, the sample under a line. */
export function Kpi({ icon, label, value, unit, foot }: KpiProps) {
  const labelId = useId();
  return (
    <div role="group" aria-labelledby={labelId} className={[styles.card, styles.kpi].join(' ')}>
      <span className={styles.kpiIcon}>
        <Icon name={icon} size="xl" />
      </span>
      <span id={labelId} className={styles.kpiLabel}>
        {label}
      </span>
      <span className={styles.kpiValue}>
        {value}
        {unit ? <small className={styles.kpiUnit}>{unit}</small> : null}
      </span>
      {foot ? <span className={styles.kpiFoot}>{foot}</span> : null}
    </div>
  );
}
