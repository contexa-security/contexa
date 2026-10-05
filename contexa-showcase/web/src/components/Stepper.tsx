import { useTranslation } from 'react-i18next';
import styles from './Stepper.module.css';

const STEPS = ['step.compare', 'step.recover', 'step.explore'] as const;

interface StepperProps {
  /** Zero-based index of the current step. */
  readonly current: number;
}

/** Shows where the visitor is in the experience track; the current step is announced to screen readers. */
export function Stepper({ current }: StepperProps) {
  const { t } = useTranslation();
  return (
    <nav aria-label={t('step.progress')}>
      <ol className={styles.steps}>
        {STEPS.map((key, index) => (
          <li
            key={key}
            className={styles.step}
            data-state={index === current ? 'current' : index < current ? 'done' : 'todo'}
            aria-current={index === current ? 'step' : undefined}
          >
            <span className={styles.index}>{index + 1}</span>
            <span className={styles.label}>{t(key)}</span>
          </li>
        ))}
      </ol>
    </nav>
  );
}
