import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import type { LiveChallenge as Challenge } from '../api/types';
import { ChallengePanel } from './ChallengePanel';
import { RecoveryFlow } from './RecoveryFlow';
import { StateScreen } from './StateScreen';

interface LiveChallengeProps {
  readonly challenge: Challenge;
  readonly onRequestCode: () => void;
  readonly onAnswer: (code: string) => void;
  readonly onCancel: () => void;
  readonly onRestart: () => void;
}

/** Contexa's additional check in a live run, from asking for the code to the work coming back or the cause it did not. */
export function LiveChallenge({ challenge, onRequestCode, onAnswer, onCancel, onRestart }: LiveChallengeProps) {
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
    case 'ABANDONED':
      return null;
    default:
      return (
        <ChallengePanel challenge={challenge} onRequestCode={onRequestCode} onAnswer={onAnswer} onCancel={onCancel} />
      );
  }
}

/** The cause of a failed recovery in visitor words; an unexpected cause is shown as the system wrote it. */
function causeText(challenge: Challenge, t: TFunction): string {
  const cause = challenge.cause ?? '';
  if (cause === 'WRONG_CODE_LIMIT') {
    return t('try.cause.WRONG_CODE_LIMIT');
  }
  if (cause.startsWith('reissue ')) {
    return t('try.cause.reissue', { status: challenge.reissueStatus ?? '—' });
  }
  return t('try.cause.other', { cause });
}
