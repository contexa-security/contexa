import {
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';
import styles from './Inputs.module.css';

/** What a field hands its control: the id its label points at and the hint that describes it. */
export interface FieldControlProps {
  readonly id: string;
  readonly 'aria-describedby'?: string;
  readonly 'aria-invalid'?: boolean;
}

interface FieldProps {
  readonly label: string;
  readonly hint?: ReactNode;
  readonly error?: ReactNode;
  readonly children: (props: FieldControlProps) => ReactNode;
}

/** The name above (13/500, 6 apart), the control (40 in a form), the hint or the error under it (기획안 5.2). */
export function Field({ label, hint, error, children }: FieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const described = error || hint ? { 'aria-describedby': hintId } : {};
  return (
    <div className={styles.field}>
      <label htmlFor={id} className={styles.label}>
        {label}
      </label>
      {children({ id, ...described, ...(error ? { 'aria-invalid': true } : {}) })}
      {error || hint ? (
        <p id={hintId} className={styles.hint} data-error={error ? 'true' : undefined}>
          {error ?? hint}
        </p>
      ) : null}
    </div>
  );
}

export function TextInput({
  compact = false,
  className,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { readonly compact?: boolean }) {
  return (
    <input
      type="text"
      {...props}
      className={[styles.control, className].filter(Boolean).join(' ')}
      data-compact={compact || undefined}
    />
  );
}

/** Several lines of words (a release request's reason). */
export function TextArea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea {...props} className={[styles.control, styles.area, className].filter(Boolean).join(' ')} />
  );
}

/** A native select: 40 in a form, 34 as a list filter. */
export function Select({
  compact = false,
  className,
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement> & { readonly compact?: boolean }) {
  return (
    <select
      {...props}
      className={[styles.control, styles.select, className].filter(Boolean).join(' ')}
      data-compact={compact || undefined}
    >
      {children}
    </select>
  );
}

interface RangeProps {
  readonly label: string;
  readonly min: number;
  readonly max: number;
  readonly step?: number;
  readonly value: number;
  readonly onChange: (value: number) => void;
  /** The value as the screen writes it next to the name (a threshold, a count). */
  readonly display?: ReactNode;
}

/** A range: track 6, blue thumb 18; the value is written beside its name. */
export function Range({ label, min, max, step = 1, value, onChange, display }: RangeProps) {
  const id = useId();
  return (
    <div className={styles.field}>
      <div className={styles.rangeHead}>
        <label htmlFor={id} className={styles.label}>
          {label}
        </label>
        <output htmlFor={id} className={styles.rangeValue}>
          {display ?? value}
        </output>
      </div>
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        className={styles.range}
        onChange={(event) => onChange(Number(event.target.value))}
      />
    </div>
  );
}

/** An on/off switch (a policy condition): the blue track when on, its state read out by its role. */
export function Switch({
  label,
  checked,
  onChange,
}: {
  readonly label: string;
  readonly checked: boolean;
  readonly onChange: (checked: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      className={styles.switch}
      onClick={() => onChange(!checked)}
    >
      <span className={styles.track} aria-hidden="true">
        <span className={styles.knob} />
      </span>
      <span>{label}</span>
    </button>
  );
}
