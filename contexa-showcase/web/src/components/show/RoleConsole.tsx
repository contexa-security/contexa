import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { Role } from '../../domain/show';
import { Icon } from '../Icon';
import styles from './RoleConsole.module.css';

export interface ConsoleRow {
  readonly key: string;
  readonly label: string;
  readonly value: string;
  /** The one condition that differs from the scene before, marked so the visitor sees it first. */
  readonly changed?: boolean;
}

interface RoleConsoleProps {
  readonly role: Role;
  /** The employee whose account is used, as the work database names them. */
  readonly name: string;
  readonly rows: readonly ConsoleRow[];
  /** The visitor's request button and what goes with it. */
  readonly children?: ReactNode;
  /** The engine holds the account: the screen darkens and says why, with what the visitor can still try. */
  readonly lock?: {
    readonly title: string;
    readonly detail: string;
    readonly meta?: string;
    readonly action?: ReactNode;
  } | null;
}

/**
 * The company's document system as the visitor sees it in their role (docs/showcase/화면설계서.md scene 1): who is
 * signed in, when, from where, and what is about to be requested. The band says whose hands the account is in.
 */
export function RoleConsole({ role, name, rows, children, lock = null }: RoleConsoleProps) {
  const { t } = useTranslation();
  return (
    <section className={styles.console} data-role={role} aria-labelledby="console-title">
      <div className={styles.band}>
        <span className={styles.badge}>
          {t(role === 'attacker' ? 'show.attacker.badge' : 'show.owner.badge', { name })}
        </span>
      </div>
      <div className={styles.window}>
        <h2 id="console-title" className={styles.title}>
          {t('show.console.title')}
        </h2>
        <dl className={styles.rows}>
          {rows.map((row) => (
            <div key={row.key} className={styles.row} data-changed={row.changed === true}>
              <dt>{row.label}</dt>
              <dd>{row.value}</dd>
            </div>
          ))}
        </dl>
        <div className={styles.actions}>{children}</div>
        {lock ? (
          <div className={styles.lock} role="alert">
            <Icon name="lock" className={styles.lockIcon} />
            <p className={styles.lockTitle}>{lock.title}</p>
            <p className={styles.lockDetail}>{lock.detail}</p>
            {lock.meta ? <p className={styles.lockMeta}>{lock.meta}</p> : null}
            {lock.action ?? null}
          </div>
        ) : null}
      </div>
    </section>
  );
}
