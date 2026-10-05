import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import type { LiveChallenge, LiveRunView } from '../api/types';
import { CONTROL_ORDER } from '../domain/verdict';
import { ChallengePanel } from './ChallengePanel';
import { OutcomeStrip } from './OutcomeStrip';
import { RecoveryFlow } from './RecoveryFlow';
import { StateScreen } from './StateScreen';
import styles from './LiveRunPanel.module.css';

interface LiveRunPanelProps {
  readonly run: LiveRunView;
  readonly title: string;
  readonly onRequestCode: () => void;
  readonly onAnswer: (code: string) => void;
  readonly onCancel: () => void;
  readonly onRestart: () => void;
}

/**
 * A live run as it happens (P3, P4): its place in the queue, each control's result as it arrives, Contexa's additional
 * check answered by the visitor, and how the work came back. Every value shown is the live result of this run.
 */
export function LiveRunPanel({ run, title, onRequestCode, onAnswer, onCancel, onRestart }: LiveRunPanelProps) {
  const { t } = useTranslation();
  const challenge = run.challenge;
  const going = run.status === 'STARTING' || run.status === 'RUNNING';
  return (
    <section className={styles.run} aria-labelledby="run-title" aria-live="polite">
      <h2 id="run-title" className={styles.title}>
        {title}
      </h2>
      {run.status === 'QUEUED' ? (
        <p className={styles.queued} role="status">
          {t('live.queued', { position: run.queuePosition })}
        </p>
      ) : null}
      {run.steps.map((step) => (
        <div key={step.stepNo} className={styles.step}>
          <p className={styles.stepLabel}>{t('try.step', { n: step.stepNo })}</p>
          <OutcomeStrip
            outcomes={CONTROL_ORDER.flatMap((control) => {
              const layer = step.layers[control];
              return layer ? [{ control, outcome: layer.outcome }] : [];
            })}
          />
        </div>
      ))}
      {going && !challenge ? <StateScreen kind="loading" /> : null}
      {challenge ? (
        <ChallengeView
          challenge={challenge}
          onRequestCode={onRequestCode}
          onAnswer={onAnswer}
          onCancel={onCancel}
          onRestart={onRestart}
        />
      ) : null}
      {run.status === 'COMPLETED' ? (
        <div className={styles.finish}>
          <p className={styles.finishText}>{challenge?.stage === 'DONE' ? t('try.resumed') : t('try.finished')}</p>
          <button type="button" className={styles.again} onClick={onRestart}>
            {t('try.again')}
          </button>
        </div>
      ) : null}
      {run.status === 'FAILED' ? <StateScreen kind="outage" onRetry={onRestart} /> : null}
      {run.status === 'EXPIRED' ? <StateScreen kind="challengeExpired" onRetry={onRestart} /> : null}
    </section>
  );
}

interface ChallengeViewProps {
  readonly challenge: LiveChallenge;
  readonly onRequestCode: () => void;
  readonly onAnswer: (code: string) => void;
  readonly onCancel: () => void;
  readonly onRestart: () => void;
}

function ChallengeView({ challenge, onRequestCode, onAnswer, onCancel, onRestart }: ChallengeViewProps) {
  const { t } = useTranslation();
  switch (challenge.stage) {
    case 'CANCELLED':
      return <StateScreen kind="challengeCancelled" onRetry={onRequestCode} />;
    case 'EXPIRED':
      return <StateScreen kind="challengeExpired" onRetry={onRestart} />;
    case 'FAILED':
      return <StateScreen kind="recoveryFailed" onRetry={onRestart} cause={causeText(challenge, t)} />;
    case 'DONE':
      return <RecoveryFlow challenge={challenge} />;
    default:
      return (
        <ChallengePanel challenge={challenge} onRequestCode={onRequestCode} onAnswer={onAnswer} onCancel={onCancel} />
      );
  }
}

/** The cause of a failed recovery in visitor words; an unexpected cause is shown as the system wrote it. */
function causeText(challenge: LiveChallenge, t: TFunction): string {
  const cause = challenge.cause ?? '';
  if (cause === 'WRONG_CODE_LIMIT') {
    return t('try.cause.WRONG_CODE_LIMIT');
  }
  if (cause.startsWith('reissue ')) {
    return t('try.cause.reissue', { status: challenge.reissueStatus ?? '—' });
  }
  return t('try.cause.other', { cause });
}
