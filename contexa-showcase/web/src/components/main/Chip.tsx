import type { ReactNode } from 'react';
import type { ChipKind } from '../../pages/main/mainCases';
import { Icon } from '../Icon';
import styles from './Chip.module.css';

/** Each kind's icon, so a chip never tells its meaning by color alone. */
const ICONS = {
  allow: 'check',
  auth: 'key',
  block: 'lock',
  bad: 'cross',
  ok: 'check',
  wait: 'clock',
} as const;

/** A result chip of the console (v4): a soft fill, an icon and the word. */
export function Chip({ kind, children }: { readonly kind: ChipKind; readonly children: ReactNode }) {
  return (
    <span className={styles.chip} data-kind={kind}>
      <Icon name={ICONS[kind]} className={styles.icon} />
      {children}
    </span>
  );
}
