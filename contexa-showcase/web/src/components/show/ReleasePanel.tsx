import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import type { LiveRelease } from '../../api/types';
import challenge from '../ChallengePanel.module.css';
import styles from './ReleasePanel.module.css';

interface ReleasePanelProps {
  readonly release: LiveRelease;
  /** The reason the request is prefilled with; the visitor may change it. */
  readonly defaultReason: string;
  readonly onStart: () => void;
  readonly onAnswer: (code: string) => void;
  readonly onRequest: (reason: string) => void;
  readonly onApprove: () => void;
}

const MAX_REASON = 300;

/**
 * The release of a block as the real employee lives it (ADR-33): the engine's own check of the blocked account with the
 * code from the demo inbox, the release request with a reason, then the visitor switches seats and approves it as the
 * security administrator, reading what the engine's administrator API returns. Every step calls the engine's endpoints.
 */
export function ReleasePanel({
  release,
  defaultReason,
  onStart,
  onAnswer,
  onRequest,
  onApprove,
}: ReleasePanelProps) {
  const { t } = useTranslation();
  const [reason, setReason] = useState(defaultReason);

  function submit(event: FormEvent) {
    event.preventDefault();
    const filed = reason.trim();
    if (filed) {
      onRequest(filed.slice(0, MAX_REASON));
    }
  }

  if (release.stage === 'REQUESTED' || release.stage === 'APPROVING') {
    const block = release.block;
    return (
      <section className={styles.admin} aria-labelledby="release-admin-title">
        <p className={styles.badge}>{t('show.release.adminBadge', { name: release.approverName ?? '—' })}</p>
        <h2 id="release-admin-title" className={challenge.title}>
          {t('show.release.adminTitle')}
        </h2>
        <p className={challenge.body}>{t('show.release.adminLead')}</p>
        <dl className={styles.record}>
          <div>
            <dt>{t('show.release.adminUser')}</dt>
            <dd>{block?.username ?? '—'}</dd>
          </div>
          <div>
            <dt>{t('show.release.adminReasoning')}</dt>
            <dd>
              <span className={styles.original}>{t('reason.engineOriginal')}</span>
              <span lang="en">{block?.reasoning ?? '—'}</span>
            </dd>
          </div>
          <div>
            <dt>{t('show.release.adminMfa')}</dt>
            <dd>{block?.mfaVerified ? t('show.release.adminMfaDone') : t('show.release.adminMfaNone')}</dd>
          </div>
          <div>
            <dt>{t('show.release.adminReason')}</dt>
            <dd>{block?.unblockReason ?? '—'}</dd>
          </div>
        </dl>
        {release.stage === 'REQUESTED' ? (
          <div className={challenge.actions}>
            <button type="button" className={challenge.primary} onClick={onApprove}>
              {t('show.release.approve')}
            </button>
          </div>
        ) : (
          <p className={challenge.body} role="status">
            {t('show.release.approving')}
          </p>
        )}
      </section>
    );
  }

  return (
    <section className={challenge.panel} aria-labelledby="release-title" data-stage={release.stage}>
      <h2 id="release-title" className={challenge.title}>
        {t('show.release.title')}
      </h2>
      <p className={challenge.body}>{t('show.release.body')}</p>
      {release.stage !== 'VERIFIED' ? (
        <p className={challenge.timer} role="timer">
          {t('try.challenge.secondsLeft', { seconds: release.secondsLeft })}
        </p>
      ) : null}
      {release.stage === 'BLOCKED' ? (
        <div className={challenge.actions}>
          <button type="button" className={challenge.primary} onClick={onStart}>
            {t('show.release.start')}
          </button>
        </div>
      ) : null}
      {release.stage === 'CODE_SHOWN' && release.code ? (
        <section className={challenge.inbox} aria-label={t('try.challenge.inbox')}>
          <p className={challenge.inboxLabel}>{t('try.challenge.inbox')}</p>
          <p className={challenge.inboxFrom}>{t('try.challenge.inboxFrom')}</p>
          <p className={challenge.code} data-testid="release-code">
            {release.code}
          </p>
          <p className={challenge.inboxNote}>{t('try.challenge.inboxNote')}</p>
          <div className={challenge.actions}>
            <button type="button" className={challenge.primary} onClick={() => onAnswer(release.code ?? '')}>
              {t('try.challenge.useCode')}
            </button>
          </div>
          {release.error === 'WRONG_CODE' ? (
            <p className={challenge.error} role="alert">
              {t('try.challenge.wrong', { attempts: release.attempts })}
            </p>
          ) : null}
        </section>
      ) : null}
      {release.stage === 'VERIFIED' ? (
        <form className={challenge.form} onSubmit={submit}>
          <p className={challenge.body}>{t('show.release.verified')}</p>
          <label className={challenge.label} htmlFor="release-reason">
            {t('show.release.reasonLabel')}
          </label>
          <textarea
            id="release-reason"
            className={styles.reason}
            value={reason}
            maxLength={MAX_REASON}
            rows={3}
            onChange={(event) => setReason(event.target.value)}
          />
          <div className={challenge.actions}>
            <button type="submit" className={challenge.primary} disabled={!reason.trim()}>
              {t('show.release.send')}
            </button>
          </div>
        </form>
      ) : null}
    </section>
  );
}
