import type { ReactNode } from 'react';
import styles from './AgentMenuPanel.module.css';

export interface Choice<V extends string | number> {
  readonly value: V;
  readonly label: ReactNode;
}

/**
 * One choice among a few, as a group of radios framed like the agent menu's (docs/agent Agent중심-화면 AC-4a, AS-12): the
 * selected one is filled, the group has its own name for a screen reader, and every choice is in reach of 44 px.
 */
export function ChoiceGroup<V extends string | number>({
  name,
  label,
  choices,
  value,
  onChange,
}: {
  readonly name: string;
  readonly label: string;
  readonly choices: readonly Choice<V>[];
  readonly value: V;
  readonly onChange: (value: V) => void;
}) {
  return (
    <fieldset className={styles.group} role="radiogroup" aria-label={label}>
      <legend className={styles.legend}>{label}</legend>
      {choices.map((choice) => (
        <label key={choice.value} className={styles.choice} data-selected={choice.value === value || undefined}>
          <input
            type="radio"
            name={name}
            className="visually-hidden"
            value={choice.value}
            checked={choice.value === value}
            onChange={() => onChange(choice.value)}
          />
          {choice.label}
        </label>
      ))}
    </fieldset>
  );
}
