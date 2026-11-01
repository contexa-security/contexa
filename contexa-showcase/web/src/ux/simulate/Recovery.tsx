import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import type { LiveChallenge, LiveRelease } from '../../api/types';
import { formatNumber } from '../format';
import { Badge, Button, CodeChip, Field, Note, Stepper, TextArea, TextInput } from '../ui';
import type { LiveAction } from './useLiveActions';
import styles from './Recovery.module.css';

type Act = (action: LiveAction, body?: Readonly<Record<string, string>>) => Promise<boolean>;

/** How far the extra check got: asked, code received, code checked, request sent again (ST-10). */
function checkStep(stage: string): number {
  return stage === 'DONE' ? 4 : stage === 'VERIFYING' ? 2 : stage === 'CODE_SHOWN' ? 1 : 0;
}

/** The demo inbox: the code the engine sent, which in a real deployment reaches the account owner's mailbox. */
function Inbox({ code }: { readonly code: string }) {
  const { t } = useTranslation();
  return (
    <section className={styles.inbox} aria-label={t('ux.recovery.inbox')}>
      <p className={styles.inboxLabel}>{t('ux.recovery.inbox')}</p>
      <p className={styles.inboxFrom}>{t('ux.recovery.inboxFrom')}</p>
      <p className={styles.code} data-testid="inbox-code">
        {code}
      </p>
      <p className={styles.inboxNote}>{t('ux.recovery.inboxNote')}</p>
    </section>
  );
}

/**
 * The extra check (step-up authentication) as the account owner or the insider meets it (ST-10~ST-13): the code from
 * the demo inbox, typed or used as is, the wrong-code count, cancel, expiry and the request sent again. Every action
 * calls the portal's live-run endpoints; the attacker never sees this card (ST-9).
 */
export function ChallengeCard({
  challenge,
  act,
  onRestart,
  resumed,
}: {
  readonly challenge: LiveChallenge;
  readonly act: Act;
  readonly onRestart: () => void;
  /** Real records of requests that went on after the check was passed (/api/teasers CHALLENGE_OUTCOMES). */
  readonly resumed: number | null;
}) {
  const { t, i18n } = useTranslation();
  const [typed, setTyped] = useState('');
  const stage = challenge.stage;
  if (stage === 'ABANDONED' || stage === 'NO_MAILBOX') {
    return null;
  }
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (typed.trim()) {
      void act('answer', { code: typed.trim() });
    }
  };
  return (
    <section className={styles.card} aria-labelledby="challenge-title" data-stage={stage}>
      <h2 id="challenge-title" className={styles.title}>
        {t('ux.recovery.check.title')}
      </h2>
      <Stepper
        label={t('ux.recovery.check.steps')}
        steps={['asked', 'code', 'check', 'retry'].map((step) => t(`ux.recovery.check.step.${step}`))}
        current={checkStep(stage)}
      />
      {stage === 'WAITING' || stage === 'CODE_SHOWN' ? (
        <p className={styles.body}>
          {t('ux.recovery.check.body')}{' '}
          <span role="timer" className={styles.timer}>
            {t('ux.recovery.secondsLeft', { seconds: challenge.secondsLeft })}
          </span>
        </p>
      ) : null}
      {stage === 'WAITING' ? (
        <div className={styles.actions}>
          <Button variant="primary" icon="mail" onClick={() => void act('code')}>
            {t('ux.recovery.requestCode')}
          </Button>
          <Button variant="text" onClick={() => void act('cancel')}>
            {t('ux.recovery.cancel')}
          </Button>
        </div>
      ) : null}
      {stage === 'CODE_SHOWN' && challenge.code ? (
        <>
          <Inbox code={challenge.code} />
          {challenge.error === 'WRONG_CODE' ? (
            <Note tone="warn">{t('ux.recovery.wrong', { attempts: challenge.attempts })}</Note>
          ) : null}
          <div className={styles.actions}>
            <Button
              variant="primary"
              icon="check"
              onClick={() => void act('answer', { code: challenge.code ?? '' })}
            >
              {t('ux.recovery.useCode')}
            </Button>
            <Button variant="text" onClick={() => void act('cancel')}>
              {t('ux.recovery.cancel')}
            </Button>
          </div>
          <details className={styles.manual}>
            <summary>{t('ux.recovery.manual')}</summary>
            <form className={styles.form} onSubmit={submit}>
              <Field label={t('ux.recovery.codeLabel')}>
                {(props) => (
                  <TextInput
                    {...props}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    value={typed}
                    onChange={(event) => setTyped(event.target.value)}
                  />
                )}
              </Field>
              <Button type="submit">{t('ux.recovery.submit')}</Button>
            </form>
          </details>
        </>
      ) : null}
      {stage === 'VERIFYING' ? (
        <p className={styles.body} role="status">
          {t('ux.recovery.verifying')}
        </p>
      ) : null}
      {stage === 'DONE' ? (
        <p className={styles.done}>
          <Badge tone="allow" icon="check">
            {t('ux.recovery.retried', {
              count: challenge.reissueDeliveredItems ?? 0,
              n: formatNumber(challenge.reissueDeliveredItems ?? 0, i18n.language),
              status: challenge.reissueStatus ?? '—',
            })}
          </Badge>
          {resumed !== null ? (
            <span className={styles.measured}>
              {t('ux.recovery.measured', { n: formatNumber(resumed, i18n.language) })}
            </span>
          ) : null}
        </p>
      ) : null}
      {stage === 'CANCELLED' ? (
        <>
          <Note>{t('ux.recovery.cancelled')}</Note>
          <div className={styles.actions}>
            <Button onClick={() => void act('code')}>{t('ux.recovery.again')}</Button>
          </div>
        </>
      ) : null}
      {stage === 'EXPIRED' || stage === 'FAILED' ? (
        <>
          <Note tone="warn">
            {t(stage === 'EXPIRED' ? 'ux.recovery.expired' : 'ux.recovery.failed')}
            {challenge.cause ? ' ' : null}
            {challenge.cause
              ? t(`ux.recovery.cause.${challenge.cause}`, { defaultValue: challenge.cause })
              : null}
          </Note>
          <div className={styles.actions}>
            <Button onClick={onRestart}>{t('ux.recovery.restart')}</Button>
          </div>
        </>
      ) : null}
    </section>
  );
}

/** What the attacker meets: the extra check's or the release's code goes to the account owner's mailbox (ST-9, ST-14). */
export function NoMailbox({ kind }: { readonly kind: 'check' | 'release' }) {
  const { t } = useTranslation();
  return <Note icon="mail">{t(`ux.recovery.noMailbox.${kind}`)}</Note>;
}

const RELEASE_STEPS = ['verify', 'request', 'approve', 'resend'] as const;

function releaseStep(stage: string): number {
  switch (stage) {
    case 'CODE_SHOWN':
      return 0;
    case 'VERIFIED':
      return 1;
    case 'REQUESTED':
    case 'APPROVING':
      return 2;
    case 'DONE':
      return 4;
    default:
      return 0;
  }
}

/**
 * The release of a block as the account owner lives it (ST-15, ADR-33): the engine's own check with the inbox code, the
 * request with a reason, then the visitor approves it as the security administrator, reading what the engine's
 * administrator API returned. Every step calls the portal's live-run endpoints.
 */
export function ReleaseCard({
  release,
  act,
  defaultReason,
  onRestart,
}: {
  readonly release: LiveRelease;
  readonly act: Act;
  readonly defaultReason: string;
  readonly onRestart: () => void;
}) {
  const { t, i18n } = useTranslation();
  const [reason, setReason] = useState(defaultReason);
  const stage = release.stage;
  if (stage === 'ABANDONED' || stage === 'NO_MAILBOX') {
    return null;
  }
  const block = release.block;
  return (
    <section className={styles.card} aria-labelledby="release-title" data-stage={stage}>
      <h2 id="release-title" className={styles.title}>
        {t('ux.recovery.release.title')}
      </h2>
      <Stepper
        label={t('ux.recovery.release.steps')}
        steps={RELEASE_STEPS.map((step) => t(`ux.recovery.release.step.${step}`))}
        current={releaseStep(stage)}
      />
      {stage === 'BLOCKED' ? (
        <>
          <p className={styles.body}>{t('ux.recovery.release.body')}</p>
          <div className={styles.actions}>
            <Button variant="primary" icon="key-round" onClick={() => void act('release-start')}>
              {t('ux.recovery.release.start')}
            </Button>
          </div>
        </>
      ) : null}
      {stage === 'CODE_SHOWN' && release.code ? (
        <>
          <Inbox code={release.code} />
          {release.error === 'WRONG_CODE' ? (
            <Note tone="warn">{t('ux.recovery.wrong', { attempts: release.attempts })}</Note>
          ) : null}
          <div className={styles.actions}>
            <Button
              variant="primary"
              icon="check"
              onClick={() => void act('answer', { code: release.code ?? '' })}
            >
              {t('ux.recovery.useCode')}
            </Button>
          </div>
        </>
      ) : null}
      {stage === 'VERIFIED' ? (
        <form
          className={styles.form}
          onSubmit={(event) => {
            event.preventDefault();
            if (reason.trim()) {
              void act('release-request', { reason: reason.trim().slice(0, 300) });
            }
          }}
        >
          <p className={styles.body}>{t('ux.recovery.release.verified')}</p>
          <Field label={t('ux.recovery.release.reason')}>
            {(props) => (
              <TextArea
                {...props}
                rows={3}
                maxLength={300}
                value={reason}
                onChange={(event) => setReason(event.target.value)}
              />
            )}
          </Field>
          <div className={styles.actions}>
            <Button
              type="submit"
              variant="primary"
              {...(reason.trim() ? {} : { disabledReason: t('ux.recovery.release.needReason') })}
            >
              {t('ux.recovery.release.send')}
            </Button>
          </div>
        </form>
      ) : null}
      {stage === 'REQUESTED' || stage === 'APPROVING' ? (
        <section className={styles.admin} aria-labelledby="release-admin-title">
          <Badge tone="sel" icon="shield-check">
            {t('ux.recovery.release.admin', { name: release.approverName ?? '—' })}
          </Badge>
          <h3 id="release-admin-title" className={styles.adminTitle}>
            {t('ux.recovery.release.adminTitle')}
          </h3>
          <p className={styles.body}>{t('ux.recovery.release.adminLead')}</p>
          <dl className={styles.record}>
            <dt>{t('ux.recovery.release.user')}</dt>
            <dd>{block?.username ? <CodeChip value={block.username} /> : '—'}</dd>
            <dt>{t('ux.recovery.release.why')}</dt>
            <dd>
              <Badge tone="line">{t('ux.recovery.original')}</Badge>{' '}
              <span lang="en">{block?.reasoning ?? '—'}</span>
            </dd>
            <dt>{t('ux.recovery.release.mfa')}</dt>
            <dd>{t(block?.mfaVerified ? 'ux.recovery.release.mfaDone' : 'ux.recovery.release.mfaNone')}</dd>
            <dt>{t('ux.recovery.release.given')}</dt>
            <dd>{block?.unblockReason ?? '—'}</dd>
          </dl>
          {stage === 'REQUESTED' ? (
            <div className={styles.actions}>
              <Button variant="primary" icon="badge-check" onClick={() => void act('release-approve')}>
                {t('ux.recovery.release.approve')}
              </Button>
            </div>
          ) : (
            <p className={styles.body} role="status">
              {t('ux.recovery.release.approving')}
            </p>
          )}
        </section>
      ) : null}
      {stage === 'DONE' ? (
        <p className={styles.done}>
          <Badge tone="allow" icon="check">
            {t('ux.recovery.release.done', {
              count: release.reissueDeliveredItems ?? 0,
              n: formatNumber(release.reissueDeliveredItems ?? 0, i18n.language),
              status: release.reissueStatus ?? '—',
            })}
          </Badge>
        </p>
      ) : null}
      {stage === 'EXPIRED' || stage === 'FAILED' ? (
        <>
          <Note tone="warn">
            {t(stage === 'EXPIRED' ? 'ux.recovery.expired' : 'ux.recovery.failed')}
            {release.cause ? ' ' : null}
            {release.cause ? t(`ux.recovery.cause.${release.cause}`, { defaultValue: release.cause }) : null}
          </Note>
          <div className={styles.actions}>
            <Button onClick={onRestart}>{t('ux.recovery.restart')}</Button>
          </div>
        </>
      ) : null}
    </section>
  );
}
