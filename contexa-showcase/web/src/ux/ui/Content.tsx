import { useId, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from './Button';
import { Icon, type UxIconName } from './Icon';
import styles from './Content.module.css';

/**
 * The guide line (기획안 5.2 안내 줄): icon 16 + words 14 on surface-2, radius 8, for the source, the sample and the
 * scope. A warning keeps the neutral box and only its icon turns orange (6.2 색의 뜻 규칙).
 */
export function Note({
  tone = 'neutral',
  icon,
  children,
}: {
  readonly tone?: 'neutral' | 'warn';
  readonly icon?: UxIconName;
  readonly children: ReactNode;
}) {
  return (
    <div role="note" className={styles.note} data-tone={tone}>
      <Icon
        name={icon ?? (tone === 'warn' ? 'triangle-alert' : 'info')}
        size="md"
        className={styles.noteIcon}
      />
      <div className={styles.noteText}>{children}</div>
    </div>
  );
}

export interface KeyValueItem {
  readonly label: ReactNode;
  readonly value: ReactNode;
}

/** Names 132 wide and their values, 10 between lines, 14; a list of figures aligns its values to the end. */
export function KeyValue({
  items,
  alignEnd = false,
}: {
  readonly items: readonly KeyValueItem[];
  readonly alignEnd?: boolean;
}) {
  return (
    <dl className={styles.kv} data-align={alignEnd ? 'end' : undefined}>
      {items.map((item, index) => (
        <div key={index} className={styles.kvRow}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export type BarTone =
  'brand' | 'link' | 'allow' | 'stepup' | 'hold' | 'block' | 'none' | 'waf' | 'iam' | 'rule' | 'approval';

/** A share from 0 to 1 (a risk score, a rate), drawn as a meter with its value for assistive technology. */
export function Bar({
  label,
  value,
  tone = 'link',
  thick = false,
}: {
  readonly label: string;
  readonly value: number;
  readonly tone?: BarTone;
  readonly thick?: boolean;
}) {
  const share = Math.min(1, Math.max(0, value));
  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={1}
      aria-valuenow={share}
      className={styles.bar}
      data-thick={thick || undefined}
    >
      <span className={styles.fill} data-tone={tone} style={{ inlineSize: `${share * 100}%` }} />
    </div>
  );
}

export interface Segment {
  readonly label: string;
  readonly value: number;
  readonly tone: BarTone;
}

/**
 * A distribution (the verdict mix, the controls' blocks): one stacked bar and its legend with the counts, so the figure
 * never depends on colour or on the drawing alone.
 */
export function StackedBar({
  label,
  segments,
  format,
}: {
  readonly label: string;
  readonly segments: readonly Segment[];
  readonly format: (value: number) => string;
}) {
  const legendId = useId();
  const total = segments.reduce((sum, segment) => sum + segment.value, 0);
  return (
    <div className={styles.stacked}>
      <div className={styles.bar} data-thick="true" aria-hidden="true">
        {segments.map((segment) => (
          <span
            key={segment.label}
            className={styles.fill}
            data-tone={segment.tone}
            style={{ inlineSize: total > 0 ? `${(segment.value / total) * 100}%` : '0%' }}
          />
        ))}
      </div>
      <ul id={legendId} aria-label={label} className={styles.legend}>
        {segments.map((segment) => (
          <li key={segment.label}>
            <span className={styles.swatch} data-tone={segment.tone} aria-hidden="true" />
            {segment.label} <b className={styles.legendValue}>{format(segment.value)}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** The skeleton of a list being read, with the word for assistive technology. */
export function Loading({ rows = 3 }: { readonly rows?: number }) {
  const { t } = useTranslation();
  return (
    <div role="status" aria-busy="true" className={styles.loading}>
      <span className="ux-sr-only">{t('ux.state.loading')}</span>
      {Array.from({ length: rows }, (_, index) => (
        <span key={index} className={styles.skeleton} aria-hidden="true" />
      ))}
    </div>
  );
}

export function EmptyState({
  children,
  action,
}: {
  readonly children?: ReactNode;
  readonly action?: ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <div className={styles.state}>
      <Icon name="folder-open" size="xxl" className={styles.stateIcon} />
      <p className={styles.stateText}>{children ?? t('ux.state.empty')}</p>
      {action}
    </div>
  );
}

/** A failed read, said at once with the way back (기획안 13: errors are never hidden in a window). */
export function ErrorState({
  children,
  onRetry,
}: {
  readonly children?: ReactNode;
  readonly onRetry?: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div role="alert" className={styles.state}>
      <Icon name="circle-alert" size="xxl" className={styles.stateIcon} />
      <p className={styles.stateText}>{children ?? t('ux.state.error')}</p>
      {onRetry ? (
        <Button size="sm" icon="refresh-cw" onClick={onRetry}>
          {t('ux.state.retry')}
        </Button>
      ) : null}
    </div>
  );
}
