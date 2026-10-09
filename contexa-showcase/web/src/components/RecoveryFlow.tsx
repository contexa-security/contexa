import { useTranslation } from 'react-i18next';
import type { LiveChallenge } from '../api/types';
import { OUTCOME_KEYS } from '../domain/verdict';
import styles from './RecoveryFlow.module.css';

const COUNT = new Intl.NumberFormat('en-US');

interface RecoveryFlowProps {
  readonly challenge: LiveChallenge;
}

/**
 * Deck p.12: held, identity check, work resumes, back to work, each with the measured time from the moment the check
 * came back. The third step shows the engine's own handling of the re-issued request, never a decision made up here.
 */
export function RecoveryFlow({ challenge }: RecoveryFlowProps) {
  const { t } = useTranslation();
  const ms = (value: number | null) => (value === null ? '—' : COUNT.format(value));
  const steps = [
    { key: 'restricted', title: t('flow.restricted'), note: t('flow.restrictedNote'), at: 0 },
    {
      key: 'verify',
      title: t('flow.verify'),
      note: t('flow.verifyNote', {
        requested: ms(challenge.codeRequestedMs),
        verified: ms(challenge.verifiedMs),
      }),
      at: challenge.verifiedMs,
    },
    {
      key: 'resume',
      title: t('flow.resume'),
      note: t('flow.resumeNote', { sent: ms(challenge.reissueSentMs) }),
      at: challenge.reissueSentMs,
    },
    {
      key: 'back',
      title: t('flow.back'),
      note: t('flow.backNote', {
        outcome: challenge.reissueOutcome ? t(OUTCOME_KEYS[challenge.reissueOutcome]) : '—',
        status: challenge.reissueStatus ?? '—',
      }),
      at: challenge.reissueDoneMs,
    },
  ];
  return (
    <section className={styles.flow} aria-labelledby="flow-title">
      <h2 id="flow-title" className={styles.title}>
        {t('flow.title')}
      </h2>
      <ol className={styles.steps}>
        {steps.map((step, index) => (
          <li key={step.key} className={styles.step} data-last={index === steps.length - 1}>
            <span className={styles.number}>{index + 1}</span>
            <span className={styles.at}>t+{ms(step.at)} ms</span>
            <strong className={styles.stepTitle}>{step.title}</strong>
            <span className={styles.note}>{step.note}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
