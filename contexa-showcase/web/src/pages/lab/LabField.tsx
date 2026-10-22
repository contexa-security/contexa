import { useId, type ReactElement, type ReactNode } from 'react';
import styles from './LabScreens.module.css';

interface LabFieldProps {
  /** The input's name, shown over it. */
  readonly label: ReactNode;
  /** Draws the input with the id its label points at. */
  readonly children: (id: string) => ReactElement;
}

/** One input of a lab screen with its name over it, the name tied to the input (a list, a value, a number). */
export function LabField({ label, children }: LabFieldProps) {
  const id = useId();
  return (
    <div className={styles.field}>
      <label htmlFor={id}>{label}</label>
      {children(id)}
    </div>
  );
}
