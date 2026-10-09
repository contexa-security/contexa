import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import styles from './StateScreen.module.css';

export type StateKind =
  | 'loading'
  | 'error'
  | 'notReady'
  | 'queued'
  | 'waiting'
  | 'outage'
  | 'challengeCancelled'
  | 'challengeExpired'
  | 'dailyLimit'
  | 'paused'
  | 'recoveryFailed'
  | 'liveClosed';

interface StateSpec {
  readonly message: string;
  /** Polite live region for states that resolve by themselves, assertive for states that need the visitor. */
  readonly live: 'status' | 'alert';
  readonly spinner?: true;
  readonly retry?: string;
  readonly record?: string;
}

/**
 * Deck p.20: every blocked moment names what happened in plain words and shows the next action. Waiting for the
 * decision and a temporary fault use different words; no state ends on an error alone, because the stored real run
 * of the same combination is offered wherever the caller has one.
 */
const SPECS: Readonly<Record<StateKind, StateSpec>> = {
  loading: { message: 'state.loading', live: 'status', spinner: true },
  error: { message: 'state.error', live: 'alert', retry: 'state.retry' },
  notReady: { message: 'state.notReady', live: 'alert' },
  // The queue (common-2): the place, about how long until the run starts, and a turn notification where one exists.
  queued: { message: 'state.queuePosition', live: 'status', spinner: true },
  // Waiting for the decision has no button: the screen goes on by itself when the decision comes (common-2).
  waiting: { message: 'state.waiting', live: 'status', spinner: true },
  outage: { message: 'state.outage', live: 'alert', retry: 'state.retry', record: 'state.viewRecord' },
  challengeCancelled: {
    message: 'state.challengeCancelled',
    live: 'alert',
    retry: 'state.retryChallenge',
    record: 'state.viewRecord',
  },
  challengeExpired: {
    message: 'state.challengeExpired',
    live: 'alert',
    retry: 'state.restart',
    record: 'state.viewRecord',
  },
  dailyLimit: { message: 'state.dailyLimit', live: 'alert', record: 'state.viewRecord' },
  paused: { message: 'state.paused', live: 'alert', record: 'state.viewSameRecord' },
  recoveryFailed: { message: 'state.recoveryFailed', live: 'alert', retry: 'state.resetRetry' },
  // Live runs are switched off on this site: say so and lead to the stored real runs.
  liveClosed: { message: 'explore.liveOff', live: 'status', record: 'state.viewRecord' },
};

interface StateScreenProps {
  readonly kind: StateKind;
  /** The state's own retry: try again, confirm again, start from the first request, or reset and try again. */
  readonly onRetry?: () => void;
  /** Route of the stored real run to continue with. */
  readonly recordTo?: string;
  /** Shown on the daily limit only when signing in really raises the limit. */
  readonly onSignIn?: () => void;
  /** Shown while live runs pause only when a turn notification really exists. */
  readonly onNotify?: () => void;
  /** Why the work could not continue, in visitor words; folded under "see the cause". */
  readonly cause?: string;
  /** About how many seconds are left, as the server estimated them from records; omitted when it gave none. */
  readonly remainingSeconds?: number | null;
  readonly queuePosition?: number;
}

export function StateScreen({
  kind,
  onRetry,
  recordTo,
  onSignIn,
  onNotify,
  cause,
  remainingSeconds,
  queuePosition,
}: StateScreenProps) {
  const { t } = useTranslation();
  const spec = SPECS[kind];
  const retry = spec.retry && onRetry ? spec.retry : null;
  const record = spec.record && recordTo ? { label: spec.record, to: recordTo } : null;
  const signIn = kind === 'dailyLimit' && onSignIn ? onSignIn : null;
  const notify = (kind === 'paused' || kind === 'queued') && onNotify ? onNotify : null;
  const anyAction = retry !== null || record !== null || signIn !== null || notify !== null;
  // The stored run is the main action when nothing else is offered, except while the decision is still coming.
  const recordIsPrimary = retry === null && kind !== 'waiting';

  return (
    <section className={styles.state} data-kind={kind} role={spec.live}>
      {spec.spinner ? <span className={styles.spinner} aria-hidden="true" /> : null}
      <p className={styles.message}>{t(spec.message, { position: queuePosition })}</p>
      {(kind === 'waiting' || kind === 'queued') &&
      remainingSeconds !== undefined &&
      remainingSeconds !== null ? (
        <p className={styles.detail}>{t('state.waitingRemaining', { seconds: remainingSeconds })}</p>
      ) : null}
      {kind === 'paused' ? <p className={styles.detail}>{t('state.pausedWhy')}</p> : null}
      {kind === 'paused' && queuePosition !== undefined ? (
        <p className={styles.detail}>{t('state.queuePosition', { position: queuePosition })}</p>
      ) : null}
      {kind === 'recoveryFailed' && cause ? (
        <details className={styles.cause}>
          <summary>{t('state.cause')}</summary>
          <p>{cause}</p>
        </details>
      ) : null}
      {kind === 'loading' ? null : (
        <div className={styles.actions}>
          {retry ? (
            <button type="button" className={styles.action} onClick={onRetry}>
              {t(retry)}
            </button>
          ) : null}
          {record ? (
            <Link className={recordIsPrimary ? styles.actionLink : styles.link} to={record.to}>
              {t(record.label)}
            </Link>
          ) : null}
          {signIn ? (
            <button type="button" className={styles.secondary} onClick={signIn}>
              {t('state.signInMore')}
            </button>
          ) : null}
          {notify ? (
            <button type="button" className={styles.secondary} onClick={notify}>
              {t('state.notifyTurn')}
            </button>
          ) : null}
          {anyAction || kind === 'waiting' || kind === 'queued' ? null : (
            <Link className={styles.link} to="/">
              {t('state.home')}
            </Link>
          )}
        </div>
      )}
    </section>
  );
}
