import { useTranslation } from 'react-i18next';
import { DEVICES, EMPLOYEES, ITEMS, PRESETS, presetOf, SLOTS, TICKETS, type Selection } from '../domain/explore';
import styles from './FactPanel.module.css';

interface FactPanelProps {
  readonly selection: Selection;
  readonly onChange: (selection: Selection) => void;
}

interface ChoiceGroupProps<T extends string | number> {
  readonly label: string;
  readonly values: readonly T[];
  readonly selected: T;
  readonly word: (value: T) => string;
  readonly onSelect: (value: T) => void;
}

function ChoiceGroup<T extends string | number>({ label, values, selected, word, onSelect }: ChoiceGroupProps<T>) {
  return (
    <fieldset className={styles.group}>
      <legend className={styles.legend}>{label}</legend>
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
    </fieldset>
  );
}

/** Deck p.13 left: only the company's facts change; the baseline and the authentication state are read-only. */
export function FactPanel({ selection, onChange }: FactPanelProps) {
  const { t } = useTranslation();
  const preset = presetOf(selection);
  return (
    <section className={styles.panel} aria-labelledby="facts-title">
      <h2 id="facts-title" className={styles.title}>
        {t('explore.facts')}
      </h2>
      <ChoiceGroup
        label={t('explore.employee')}
        values={EMPLOYEES}
        selected={selection.employee as (typeof EMPLOYEES)[number]}
        word={(value) => t(`explore.employee.${value}`)}
        onSelect={(employee) => onChange({ ...selection, employee })}
      />
      <ChoiceGroup
        label={t('explore.slot')}
        values={SLOTS}
        selected={selection.slot}
        word={(value) => t(`explore.slot.${value}`)}
        onSelect={(slot) => onChange({ ...selection, slot })}
      />
      <ChoiceGroup
        label={t('explore.items')}
        values={ITEMS}
        selected={selection.items as (typeof ITEMS)[number]}
        word={(value) => t(`explore.items.${value}`)}
        onSelect={(items) => onChange({ ...selection, items })}
      />
      <ChoiceGroup
        label={t('explore.ticket')}
        values={TICKETS}
        selected={selection.ticket}
        word={(value) => t(`explore.ticket.${value}`)}
        onSelect={(ticket) => onChange({ ...selection, ticket })}
      />
      <ChoiceGroup
        label={t('explore.device')}
        values={DEVICES}
        selected={selection.device}
        word={(value) => t(`explore.device.${value}`)}
        onSelect={(device) => onChange({ ...selection, device })}
      />
      <ChoiceGroup
        label={t('explore.presets')}
        values={Object.keys(PRESETS) as (keyof typeof PRESETS)[]}
        selected={preset ?? ('' as keyof typeof PRESETS)}
        word={(value) => t(`explore.preset.${value}`)}
        onSelect={(name) => onChange(PRESETS[name])}
      />
    </section>
  );
}
