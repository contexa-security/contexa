import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { Fact } from '../domain/experience';
import { DEVICES, EMPLOYEES, ITEMS, SLOTS, TICKETS, type Selection } from '../domain/explore';
import styles from './WorkConsole.module.css';

interface WorkConsoleProps {
  readonly selection: Selection;
  /** The visitor picks the facts (free play); otherwise the scene's facts are fixed. */
  readonly editable: boolean;
  readonly onChange?: (selection: Selection) => void;
  /** Facts that differ from scene 1, marked so the one change stands out. */
  readonly changed?: readonly Fact[];
  readonly sending: boolean;
  readonly disabled: boolean;
  readonly onSend: () => void;
  readonly note?: ReactNode;
  readonly children?: ReactNode;
}

/**
 * The window of the virtual company's document system the visitor works in: who is signed in, when, from which device,
 * whether an incident ticket is open, which documents, and the one button that sends the request for real.
 */
export function WorkConsole({
  selection,
  editable,
  onChange,
  changed = [],
  sending,
  disabled,
  onSend,
  note,
  children,
}: WorkConsoleProps) {
  const { t, i18n } = useTranslation();
  const count = new Intl.NumberFormat(i18n.language === 'ko' ? 'ko-KR' : 'en-US');
  const items = count.format(selection.items);

  function change(next: Partial<Selection>) {
    onChange?.({ ...selection, ...next });
  }

  const rows: { fact: Fact; label: string; value: string; choices: ReactNode }[] = [
    {
      fact: 'employee',
      label: t('exp.console.signedIn'),
      value: t(`exp.who.${selection.employee}`),
      choices: (
        <Choices
          values={EMPLOYEES}
          selected={selection.employee}
          word={(value) => t(`explore.employee.${value}`)}
          onSelect={(employee) => change({ employee })}
        />
      ),
    },
    {
      fact: 'slot',
      label: t('exp.console.time'),
      value: t(`exp.slot.${selection.slot}`),
      choices: (
        <Choices
          values={SLOTS}
          selected={selection.slot}
          word={(value) => t(`exp.slot.${value}`)}
          onSelect={(slot) => change({ slot })}
        />
      ),
    },
    {
      fact: 'device',
      label: t('exp.console.device'),
      value: t(`exp.device.${selection.device}`),
      choices: (
        <Choices
          values={DEVICES}
          selected={selection.device}
          word={(value) => t(`exp.device.${value}`)}
          onSelect={(device) => change({ device })}
        />
      ),
    },
    {
      fact: 'ticket',
      label: t('exp.console.ticket'),
      value: t(`exp.ticket.${selection.ticket}`),
      choices: (
        <Choices
          values={TICKETS}
          selected={selection.ticket}
          word={(value) => t(`exp.ticket.${value}`)}
          onSelect={(ticket) => change({ ticket })}
        />
      ),
    },
    {
      fact: 'items',
      label: t('exp.console.items'),
      value: t('exp.console.target', { items }),
      choices: (
        <Choices
          values={ITEMS}
          selected={selection.items as (typeof ITEMS)[number]}
          word={(value) => t('exp.items', { items: count.format(value) })}
          onSelect={(value) => change({ items: value })}
        />
      ),
    },
  ];

  return (
    <div className={styles.window}>
      <p className={styles.titleBar}>
        <span className={styles.dots} aria-hidden="true">
          <span />
          <span />
          <span />
        </span>
        {t('exp.console.title')}
      </p>
      {editable ? (
        <div className={styles.body}>
          {rows.map((row) => (
            <fieldset key={row.fact} className={styles.group}>
              <legend className={styles.label}>{row.label}</legend>
              {row.choices}
            </fieldset>
          ))}
        </div>
      ) : (
        <dl className={styles.body}>
          {rows.map((row) => (
            <div key={row.fact} className={styles.row} data-changed={changed.includes(row.fact)}>
              <dt className={styles.label}>{row.label}</dt>
              <dd className={styles.value}>
                {row.value}
                {changed.includes(row.fact) ? (
                  <span className={styles.changedTag}>{t('exp.console.changed')}</span>
                ) : null}
              </dd>
            </div>
          ))}
        </dl>
      )}
      <div className={styles.actions}>
        <button type="button" className={styles.send} disabled={disabled || sending} onClick={onSend}>
          {sending ? t('exp.console.sending') : t('exp.console.send', { items })}
        </button>
        {note ? <p className={styles.note}>{note}</p> : null}
        {children}
      </div>
    </div>
  );
}

interface ChoicesProps<T extends string | number> {
  readonly values: readonly T[];
  readonly selected: T;
  readonly word: (value: T) => string;
  readonly onSelect: (value: T) => void;
}

function Choices<T extends string | number>({ values, selected, word, onSelect }: ChoicesProps<T>) {
  return (
    <div className={styles.choices}>
      {values.map((value) => (
        <button
          key={value}
          type="button"
          className={styles.choice}
          aria-pressed={value === selected}
          onClick={() => onSelect(value)}
        >
          {word(value)}
        </button>
      ))}
    </div>
  );
}
