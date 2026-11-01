import { useRef, type KeyboardEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Icon } from './Icon';
import styles from './Tabs.module.css';

export interface TabItem {
  readonly id: string;
  readonly label: string;
  /** A count pill (12) after the name: the number of records the tab holds. */
  readonly count?: number;
}

interface TabsProps {
  /** Ties the tabs to their panels: the same base on <TabPanel>. */
  readonly idBase: string;
  readonly label: string;
  readonly items: readonly TabItem[];
  readonly value: string;
  readonly onChange: (id: string) => void;
}

const tabId = (base: string, id: string) => `${base}-tab-${id}`;
const panelId = (base: string, id: string) => `${base}-panel-${id}`;

/**
 * Tabs 44 high, 28 apart, 15/500 with the current one 600 and underlined in gold (기획안 5.2). Arrow keys, Home and
 * End move and select (automatic activation); only the selected tab is in the tab order. The screen keeps the choice in
 * its address (`?tab=`), so the caller owns the value.
 */
export function Tabs({ idBase, label, items, value, onChange }: TabsProps) {
  const list = useRef<HTMLDivElement>(null);
  const move = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const last = items.length - 1;
    const next =
      event.key === 'ArrowRight'
        ? index === last
          ? 0
          : index + 1
        : event.key === 'ArrowLeft'
          ? index === 0
            ? last
            : index - 1
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? last
              : null;
    const item = next === null ? undefined : items[next];
    if (!item) {
      return;
    }
    event.preventDefault();
    onChange(item.id);
    list.current?.querySelector<HTMLButtonElement>(`#${CSS.escape(tabId(idBase, item.id))}`)?.focus();
  };
  return (
    <div ref={list} role="tablist" aria-label={label} className={styles.tabs}>
      {items.map((item, index) => {
        const selected = item.id === value;
        return (
          <button
            key={item.id}
            type="button"
            role="tab"
            id={tabId(idBase, item.id)}
            aria-selected={selected}
            aria-controls={panelId(idBase, item.id)}
            tabIndex={selected ? 0 : -1}
            className={styles.tab}
            onClick={() => onChange(item.id)}
            onKeyDown={(event) => move(event, index)}
          >
            {item.label}
            {item.count !== undefined ? (
              <>
                {' '}
                <span className={styles.count}>{item.count}</span>
              </>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

export function TabPanel({
  idBase,
  id,
  children,
}: {
  readonly idBase: string;
  readonly id: string;
  readonly children: ReactNode;
}) {
  return (
    <div
      role="tabpanel"
      id={panelId(idBase, id)}
      aria-labelledby={tabId(idBase, id)}
      tabIndex={0}
      className={styles.panel}
    >
      {children}
    </div>
  );
}

interface StepperProps {
  readonly steps: readonly string[];
  /** The index of the step on view; the ones before it are finished. */
  readonly current: number;
  readonly label?: string;
}

/**
 * The steps of a run (기획안 5.2): circles 28 (the current one gold, finished ones checked), names 14, links 56. On a
 * phone only the current step keeps its name.
 */
export function Stepper({ steps, current, label }: StepperProps) {
  const { t } = useTranslation();
  return (
    <nav aria-label={label ?? t('ux.stepper.label')} className={styles.stepper}>
      <ol className={styles.steps}>
        {steps.map((step, index) => {
          const state = index < current ? 'done' : index === current ? 'now' : 'next';
          return (
            <li
              key={step}
              className={styles.step}
              data-state={state}
              aria-current={state === 'now' ? 'step' : undefined}
            >
              <span className={styles.stepMark} aria-hidden="true">
                {state === 'done' ? <Icon name="check" size="sm" /> : index + 1}
              </span>
              <span className={styles.stepLabel}>{step}</span>
              {state === 'done' ? <span className="ux-sr-only">{t('ux.stepper.done')}</span> : null}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
