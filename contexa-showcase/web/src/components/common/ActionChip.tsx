import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Icon, type IconName } from '../Icon';
import styles from './ActionChip.module.css';

interface ActionChipProps {
  /** A screen of the demo to go to. */
  readonly to?: string;
  /** A file to download (served by the portal), saved under this name. */
  readonly download?: { readonly href: string; readonly name: string };
  /** Something to do in place, when there is no address. */
  readonly onClick?: () => void;
  readonly icon?: IconName;
  /** 'sm' sits inside a row or a sentence; 'md' is the action area's secondary action. */
  readonly size?: 'sm' | 'md';
  /**
   * 'move' (outlined) goes somewhere: back, another screen. 'open' (tinted, no outline) opens more of the content it
   * sits under. 'quiet' (no outline, no tint) is offered but not urged: skip.
   */
  readonly variant?: 'move' | 'open' | 'quiet';
  readonly disabled?: boolean;
  readonly expanded?: boolean;
  readonly children: ReactNode;
}

/**
 * A secondary action drawn as a chip with its icon, never as a bare text link (2026-10-08 instruction: links, buttons
 * and events are made visible, not plain text). The one main action of a screen stays the filled button.
 */
export function ActionChip({
  to,
  download,
  onClick,
  icon,
  size = 'md',
  variant = 'move',
  disabled = false,
  expanded,
  children,
}: ActionChipProps) {
  const content = (
    <>
      {icon ? <Icon name={icon} className={styles.icon} /> : null}
      <span>{children}</span>
    </>
  );
  if (download !== undefined) {
    return (
      <a
        href={download.href}
        download={download.name}
        className={styles.chip}
        data-size={size}
        data-variant={variant}
      >
        {content}
      </a>
    );
  }
  if (to !== undefined) {
    return (
      <Link to={to} className={styles.chip} data-size={size} data-variant={variant}>
        {content}
      </Link>
    );
  }
  return (
    <button
      type="button"
      className={styles.chip}
      data-size={size}
      data-variant={variant}
      disabled={disabled}
      aria-expanded={expanded}
      onClick={onClick}
    >
      {content}
    </button>
  );
}
