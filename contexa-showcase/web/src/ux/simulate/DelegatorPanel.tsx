import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LiveAgentConfirmation } from '../../api/types';
import { formatNumber } from '../format';
import { Badge, Button, Icon, Note } from '../ui';
import styles from './Agent.module.css';

/**
 * The delegating person's answer to control D's confirmation (기획안 7.6, ST-24~ST-26): the visitor answers as the
 * person who delegated the work. The portal takes approve or reject live (DEC-26); a report is shown from a stored real
 * run on the result. After the answer the agent's request is sent again, and its answer is said here.
 */
export function DelegatorPanel({
  confirmation,
  delegator,
  answer,
}: {
  readonly confirmation: LiveAgentConfirmation;
  readonly delegator: string;
  readonly answer: (approve: boolean) => Promise<boolean>;
}) {
  const { t, i18n } = useTranslation();
  const [answering, setAnswering] = useState(false);
  const [failed, setFailed] = useState(false);
  const n = (value: number) => formatNumber(value, i18n.language);
  async function decide(approve: boolean) {
    setAnswering(true);
    setFailed(false);
    try {
      setFailed(!(await answer(approve)));
    } catch {
      setFailed(true);
    } finally {
      setAnswering(false);
    }
  }
  const asked = confirmation.stage === 'ASKED';
  return (
    <section className={styles.delegator} aria-labelledby="delegator-title" data-asked={asked || undefined}>
      <header className={styles.delegatorHead}>
        <span className={styles.delegatorIcon}>
          <Icon name="user-round-check" size="lg" />
        </span>
        <div>
          <h2 id="delegator-title" className={styles.delegatorTitle}>
            {t('ux.agent.delegator.title', { n: confirmation.stepNo })}
          </h2>
          <p className={styles.delegatorSub}>{t('ux.agent.delegator.you', { name: delegator })}</p>
        </div>
      </header>
      <dl className={styles.delegatorFacts}>
        <dt>{t('ux.agent.delegator.why')}</dt>
        <dd>
          {confirmation.trigger
            ? t(`ux.agent.trigger.${confirmation.trigger}`, { defaultValue: confirmation.trigger })
            : '—'}
        </dd>
        {confirmation.method || confirmation.target ? (
          <>
            <dt>{t('ux.agent.delegator.request')}</dt>
            <dd>
              <code className={styles.requestPath}>
                {confirmation.method ?? ''} {confirmation.target ?? ''}
              </code>
            </dd>
          </>
        ) : null}
        {asked ? (
          <>
            <dt>{t('ux.agent.delegator.left')}</dt>
            <dd role="timer">{t('ux.agent.delegator.seconds', { count: confirmation.secondsLeft, n: n(confirmation.secondsLeft) })}</dd>
          </>
        ) : null}
      </dl>

      {asked ? (
        <>
          <div className={styles.delegatorActions}>
            <Button variant="secondary" icon="check" busy={answering} onClick={() => void decide(true)}>
              {t('ux.agent.delegator.approve')}
            </Button>
            <Button variant="danger" icon="ban" busy={answering} onClick={() => void decide(false)}>
              {t('ux.agent.delegator.reject')}
            </Button>
          </div>
          <p className={styles.delegatorNote}>{t('ux.agent.delegator.reportNote')}</p>
        </>
      ) : null}

      {confirmation.stage === 'DONE' && confirmation.decision ? (
        <div className={styles.delegatorAfter}>
          <p className={styles.delegatorDecision}>
            <Badge tone={confirmation.decision === 'APPROVE' ? 'allow' : 'block'} icon={confirmation.decision === 'APPROVE' ? 'check' : 'ban'}>
              {t(`ux.agent.delegator.decided.${confirmation.decision}`)}
            </Badge>
          </p>
          <ul className={styles.afterList}>
            {confirmation.resendStatus !== null ? (
              <li>
                {t('ux.agent.delegator.resend', {
                  status: confirmation.resendStatus,
                  n: n(confirmation.resendDeliveredItems ?? 0),
                  count: confirmation.resendDeliveredItems ?? 0,
                })}
              </li>
            ) : null}
            {confirmation.decision === 'APPROVE' && confirmation.reuseStatus !== null ? (
              <li>
                {t('ux.agent.delegator.reuse', { status: confirmation.reuseStatus })}
                {confirmation.reuseRule ? <code className={styles.rule}> {confirmation.reuseRule}</code> : null}
              </li>
            ) : null}
            {confirmation.decision === 'APPROVE' && confirmation.otherStatus !== null ? (
              <li>
                {t('ux.agent.delegator.other', { status: confirmation.otherStatus })}
                {confirmation.otherRule ? <code className={styles.rule}> {confirmation.otherRule}</code> : null}
              </li>
            ) : null}
          </ul>
        </div>
      ) : null}

      {confirmation.stage === 'EXPIRED' || confirmation.stage === 'ABANDONED' || confirmation.stage === 'FAILED' ? (
        <Note tone="warn">{t(`ux.agent.delegator.ended.${confirmation.stage}`)}</Note>
      ) : null}
      {failed ? <Note tone="warn">{t('ux.live.actionFailed')}</Note> : null}
    </section>
  );
}
