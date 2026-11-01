import { useId, type MouseEvent, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Icon, type UxIconName } from './Icon';
import styles from './Button.module.css';

/**
 * The four buttons (기획안 5.2): primary (gold, one per screen), secondary, text and danger, at 32 · 36 · 44. An action
 * that cannot run now stays focusable and says why (aria-disabled + description), instead of going silent.
 */
export type ButtonVariant = 'primary' | 'secondary' | 'text' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg';

interface CommonProps {
  readonly variant?: ButtonVariant;
  readonly size?: ButtonSize;
  readonly icon?: UxIconName;
  readonly iconAfter?: UxIconName;
  /** Fills its row (the phone's bottom action, a head's actions on a phone). */
  readonly block?: boolean;
  readonly className?: string;
  readonly children: ReactNode;
}

interface ButtonProps extends CommonProps {
  readonly type?: 'button' | 'submit';
  readonly onClick?: (event: MouseEvent<HTMLButtonElement>) => void;
  /** Why the action cannot run now; the button stays in the tab order and reads this out. */
  readonly disabledReason?: string;
  /** The action is running; a second press does nothing. */
  readonly busy?: boolean;
  readonly 'aria-controls'?: string;
  readonly 'aria-expanded'?: boolean;
  /** The full name when the visible words alone repeat on the screen ("Copy code" on three code blocks). */
  readonly 'aria-label'?: string;
}

function classes(block: boolean, className?: string): string {
  return [styles.button, block ? styles.block : '', className ?? ''].filter(Boolean).join(' ');
}

interface InsideProps {
  readonly icon?: UxIconName | undefined;
  readonly iconAfter?: UxIconName | undefined;
  readonly busy?: boolean;
  readonly children: ReactNode;
}

function Inside({ icon, iconAfter, busy = false, children }: InsideProps) {
  return (
    <>
      {busy ? (
        <Icon name="loader-circle" size="md" className={styles.spin} />
      ) : icon ? (
        <Icon name={icon} size="md" />
      ) : null}
      <span className={styles.label}>{children}</span>
      {iconAfter ? <Icon name={iconAfter} size="md" /> : null}
    </>
  );
}

export function Button({
  variant = 'secondary',
  size = 'md',
  icon,
  iconAfter,
  block = false,
  className,
  children,
  type = 'button',
  onClick,
  disabledReason,
  busy = false,
  ...aria
}: ButtonProps) {
  const reasonId = useId();
  const unavailable = disabledReason !== undefined || busy;
  return (
    <>
      <button
        type={type}
        className={classes(block, className)}
        data-variant={variant}
        data-size={size}
        aria-disabled={unavailable || undefined}
        aria-busy={busy || undefined}
        aria-describedby={disabledReason ? reasonId : undefined}
        title={disabledReason}
        onClick={(event) => {
          if (unavailable) {
            event.preventDefault();
            return;
          }
          onClick?.(event);
        }}
        {...aria}
      >
        <Inside icon={icon} iconAfter={iconAfter} busy={busy}>
          {children}
        </Inside>
      </button>
      {disabledReason ? (
        <span id={reasonId} className="ux-sr-only">
          {disabledReason}
        </span>
      ) : null}
    </>
  );
}

/** A link inside the application drawn as a button (the next step, a jump to another menu). */
export function ButtonLink({
  to,
  variant = 'secondary',
  size = 'md',
  icon,
  iconAfter,
  block = false,
  className,
  children,
  label,
}: CommonProps & {
  readonly to: string;
  /** The full name when the visible words alone repeat on the screen ("Run" on four cards). */
  readonly label?: string;
}) {
  return (
    <Link
      to={to}
      className={classes(block, className)}
      data-variant={variant}
      data-size={size}
      aria-label={label}
    >
      <Inside icon={icon} iconAfter={iconAfter}>
        {children}
      </Inside>
    </Link>
  );
}

/** A link that leaves the application (documentation, the source), opened in a new tab with its icon. */
export function ButtonAnchor({
  href,
  variant = 'secondary',
  size = 'md',
  icon,
  block = false,
  className,
  children,
}: CommonProps & { readonly href: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className={classes(block, className)}
      data-variant={variant}
      data-size={size}
    >
      <Inside icon={icon} iconAfter="external-link">
        {children}
      </Inside>
    </a>
  );
}
