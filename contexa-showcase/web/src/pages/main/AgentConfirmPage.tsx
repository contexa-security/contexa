import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import {
  useAgentCase,
  useAgentCaseKey,
  useAgentSubject,
  useAgentConfirmationAnswer,
  useAgentRun,
  useAgentTry,
  type AgentResent,
} from '../../api/agentCase';
import { Term } from '../../components/common/Glossary';
import { useReferenceSnapshot } from '../../api/agentSnapshots';
import { Chip } from '../../components/main/Chip';
import { MainScreen } from '../../components/main/MainScreen';
import { SnapshotBadge } from '../../components/main/SnapshotBadge';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { Fold } from '../../components/main/Fold';
import { count } from '../../journey/format';
import {
  AGENT_PATHS,
  CONFIRMATION_RULE,
  firstStop,
  operationName,
  periodWords,
  plusMinutes,
} from './agentGroup';
import { MeasureNote } from './MeasureNote';
import { companyClock } from './mainCases';
import styles from './AgentPages.module.css';

/** The run states in which the agent's work is stored. */
const STORED = new Set(['CONFIRMING', 'COMPLETED']);
/** The four steps of a confirmation (설계서 4.3 AD-4). */
const PROGRESS = ['check', 'asked', 'answer', 'result'] as const;

type Shown = 'none' | 'asked' | 'approved' | 'rejected' | 'unanswered' | 'through' | 'blocked';

/**
 * 6-4, what went to the delegating person (docs/agent 화면설계 4.3 AD-4, A7-3). When control D asked for a
 * confirmation the screen is the delegating person's confirmation (core AC-2's fields): the work given, the request,
 * the engine's difference, the reason, the time left, and approve or reject, answered by the visitor as the employee.
 * After the answer, the authorization record, the request the agent sent again with the confirmation, and the engine
 * refusing the same confirmation a second time and on another request (A5-9). The headline follows the result.
 */
export default function AgentConfirmPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const caseKey = useAgentCaseKey();
  const agentCase = useAgentCase(caseKey);
  const subject = useAgentSubject();
  const tried = useAgentTry(caseKey);
  const answer = useAgentConfirmationAnswer();
  const [answering, setAnswering] = useState(false);
  const live = tried.live;
  const asking = live?.agentConfirmation ?? null;
  const ownReadable = tried.runId !== null && (live === null || STORED.has(live.status));
  const runId = ownReadable ? tried.runId : (agentCase.data?.recorded?.runId ?? null);
  const record = useAgentRun(runId, asking?.stage ?? null);
  // AC-5: with no run of the visitor's and no recording of the case, a frozen real run stands in (no model is called).
  const snapshot = useReferenceSnapshot(
    runId === null && tried.live === null && !agentCase.isPending && !tried.pending,
  );
  const run = record.data ?? snapshot?.run ?? null;
  const stored = run?.confirmation ?? null;
  const stop = firstStop(run);
  const delegation = agentCase.data?.delegation ?? null;
  const asked = live?.status === 'CONFIRMING' && asking?.stage === 'ASKED';
  const decision = asking?.decision ?? stored?.decision ?? null;
  const shown: Shown = asked
    ? 'asked'
    : decision === 'APPROVE'
      ? 'approved'
      : decision === 'REJECT'
        ? 'rejected'
        : run === null
          ? 'none'
          : stop === null
            ? 'through'
            : stop.outcomes.D?.rule === CONFIRMATION_RULE
              ? 'unanswered'
              : 'blocked';
  const trigger = asking?.trigger ?? stored?.trigger ?? null;
  const ended = delegation ? plusMinutes(run?.companyTime, delegation.validUntilMinutes) : null;
  const requestAt = stop?.companyTime ?? null;
  const authorization = asking?.authorizationId ?? stored?.after?.authorizationId ?? null;
  const resend =
    resent(asking?.resendStatus, asking?.resendOutcome, asking?.resendDeliveredItems, null) ??
    stored?.resend ??
    null;
  const reuse = resent(asking?.reuseStatus, null, null, asking?.reuseRule) ?? stored?.reuse ?? null;
  const other = resent(asking?.otherStatus, null, null, asking?.otherRule) ?? stored?.other ?? null;
  const pending = agentCase.isPending || tried.pending || (runId !== null && record.isPending);

  async function decide(approve: boolean) {
    setAnswering(true);
    try {
      await answer(approve);
    } finally {
      setAnswering(false);
    }
  }

  return (
    <MainScreen
      subject={subject}
      title={t(`main.6-4.title.${shown}`)}
      intro={t(shown === 'none' ? 'main.6-4.intro.none' : 'main.6-4.intro')}
      waiting={asked ? { label: t('main.6-4.waiting'), hint: t('main.6-4.waitingHint') } : null}
    >
      {pending ? <StateScreen kind="loading" /> : null}
      {!pending && shown === 'none' ? (
        <p className={styles.note}>
          <Link to={AGENT_PATHS.request}>{t('main.6-2.toRequest')}</Link>
        </p>
      ) : null}
      {!pending && shown !== 'none' ? (
        <div className={styles.stack}>
          <p className={styles.subjectLine}>
            <Chip kind="auth">
              <Term term="delegatorCheck">{t('main.agent.delegatorCheck')}</Term>
            </Chip>
            {snapshot && record.data === undefined ? (
              <SnapshotBadge snapshot={snapshot} />
            ) : runId ? (
              tried.runId === runId ? (
                <SourceBadge kind="run" runId={runId} />
              ) : (
                <SourceBadge kind="repeated" runs={1} runId={runId} />
              )
            ) : null}
          </p>
          {shown === 'asked' || shown === 'approved' || shown === 'rejected' || shown === 'unanswered' ? (
            <ol className={styles.progress} aria-label={t('main.6-4.progress')}>
              {PROGRESS.map((step, index) => {
                const reached =
                  index < 2 ||
                  (index === 2 && shown !== 'asked') ||
                  (index === 3 && (shown === 'approved' || shown === 'rejected'));
                return (
                  <li key={step} className={styles.progressStep} data-reached={reached || undefined}>
                    {t(`main.6-4.step.${step}`)}
                  </li>
                );
              })}
            </ol>
          ) : null}
          {shown === 'asked' || shown === 'approved' || shown === 'rejected' || shown === 'unanswered' ? (
            <div className={styles.cards}>
              <section className={styles.card} data-mark aria-labelledby="confirm-difference">
                <h2 id="confirm-difference" className={styles.label}>
                  {t('main.6-3.difference')}
                </h2>
                <p className={styles.body}>
                  {trigger && i18n.exists(`main.agent.trigger.${trigger}`)
                    ? t(`main.agent.trigger.${trigger}`)
                    : (trigger ?? '-')}
                </p>
              </section>
            </div>
          ) : null}
          {shown === 'asked' && asking ? (
            <section className={styles.callout} aria-labelledby="confirm-answer">
              <h2 id="confirm-answer" className={styles.label}>
                {t('main.6-4.answer')}
              </h2>
              <p className={styles.body}>
                {t('main.6-4.left', { seconds: count(asking.secondsLeft, i18n.language) })}
              </p>
              <div className={styles.buttons}>
                <button
                  type="button"
                  className={styles.primary}
                  disabled={answering}
                  onClick={() => void decide(true)}
                >
                  {t('main.6-4.approve')}
                </button>
                <button
                  type="button"
                  className={styles.secondary}
                  disabled={answering}
                  onClick={() => void decide(false)}
                >
                  {t('main.6-4.reject')}
                </button>
              </div>
            </section>
          ) : null}
          {shown === 'asked' || shown === 'approved' || shown === 'rejected' || shown === 'unanswered' ? (
            <Fold name="confirm-record" summary={t('main.6-4.recordFold')}>
              {shown === 'approved' || shown === 'rejected' ? (
                <section className={styles.card} aria-labelledby="confirm-result">
                  <h2 id="confirm-result" className={styles.label}>
                    {t('main.6-4.result')}
                  </h2>
                  <dl className={styles.rows}>
                    <div className={styles.row}>
                      <dt className={styles.rowName}>
                        {t(shown === 'approved' ? 'main.6-4.resent' : 'main.6-4.resentRejected')}
                      </dt>
                      <dd className={styles.rowValue}>{resentWords(t, resend)}</dd>
                    </div>
                    {shown === 'approved' ? (
                      <>
                        <div className={styles.row}>
                          <dt className={styles.rowName}>{t('main.6-4.reuse')}</dt>
                          <dd className={styles.rowValue}>{resentWords(t, reuse)}</dd>
                        </div>
                        <div className={styles.row}>
                          <dt className={styles.rowName}>{t('main.6-4.other')}</dt>
                          <dd className={styles.rowValue}>{resentWords(t, other)}</dd>
                        </div>
                      </>
                    ) : null}
                  </dl>
                  <p className={styles.note}>{t('main.6-4.cost')}</p>
                </section>
              ) : null}
              <p className={styles.note}>{t('main.6-3.byRecord')}</p>
              {trigger === 'DELEGATION_ENDED' && ended ? (
                <p className={styles.note}>
                  {t('main.6-3.endedVsAt', {
                    ended: companyClock(t, ended),
                    at: companyClock(t, requestAt) ?? '-',
                  })}
                </p>
              ) : null}
              <div className={styles.cards}>
                <section className={styles.card} aria-labelledby="confirm-work">
                  <h2 id="confirm-work" className={styles.label}>
                    <Term term="delegationRecord">{t('main.agent.work')}</Term>
                  </h2>
                  {delegation ? (
                    <dl className={styles.rows}>
                      <div className={styles.row}>
                        <dt className={styles.rowName}>{t('main.agent.objective')}</dt>
                        <dd className={styles.rowValue}>{delegation.summary[language]}</dd>
                      </div>
                      <div className={styles.row}>
                        <dt className={styles.rowName}>{t('main.agent.scope')}</dt>
                        <dd className={styles.rowValue}>
                          {t('main.agent.scopeValue', {
                            operations: delegation.operations
                              .map((operation) => operationName(t, (key) => i18n.exists(key), operation))
                              .join(', '),
                            resources: delegation.resources.join(', '),
                          })}
                        </dd>
                      </div>
                      <div className={styles.row}>
                        <dt className={styles.rowName}>{t('main.agent.period')}</dt>
                        <dd className={styles.rowValue}>{periodWords(t, delegation)}</dd>
                      </div>
                    </dl>
                  ) : null}
                </section>
                <section className={styles.card} aria-labelledby="confirm-request">
                  <h2 id="confirm-request" className={styles.label}>
                    {t('main.6-4.request')}
                  </h2>
                  <p className={styles.body}>
                    <code className={styles.path}>
                      {asking?.method ?? 'GET'} {asking?.target ?? stop?.path ?? ''}
                    </code>
                  </p>
                  <p className={styles.note}>
                    {t('main.6-3.at')}: {companyClock(t, requestAt) ?? '-'}
                  </p>
                </section>
              </div>
              {shown === 'approved' || shown === 'rejected' ? (
                <dl className={styles.rows}>
                  <div className={styles.row}>
                    <dt className={styles.rowName}>{t('main.6-4.authorization')}</dt>
                    <dd className={styles.rowValue}>
                      <code className={styles.path}>{authorization ?? t('main.6-4.noAuthorization')}</code>
                    </dd>
                  </div>
                  {(
                    [
                      ['main.6-4.resent', resend],
                      ['main.6-4.reuse', reuse],
                      ['main.6-4.other', other],
                    ] as const
                  ).map(([name, value]) =>
                    value?.ruleId && value.httpStatus !== null && value.httpStatus >= 300 ? (
                      <div key={name} className={styles.row}>
                        <dt className={styles.rowName}>{t('main.6-4.refusedBy', { what: t(name) })}</dt>
                        <dd className={styles.rowValue}>
                          <code className={styles.path}>{value.ruleId}</code>
                        </dd>
                      </div>
                    ) : null,
                  )}
                </dl>
              ) : null}
            </Fold>
          ) : null}
          {shown === 'unanswered' ? (
            <p className={styles.body}>
              {t(`main.6-4.unansweredWhy.${unansweredWhy(stored?.reason ?? asking?.stage ?? null)}`)}
            </p>
          ) : null}
          {shown === 'through' ? (
            <p className={styles.body}>
              {t(
                agentCase.data?.classification === 'THREAT'
                  ? 'main.6-4.throughThreat'
                  : 'main.6-4.throughNormal',
              )}
            </p>
          ) : null}
          {shown === 'blocked' ? <p className={styles.body}>{t('main.6-4.blockedLine')}</p> : null}
          <MeasureNote own={ownReadable} stopReason={run?.stopReason ?? null} />
        </div>
      ) : null}
    </MainScreen>
  );
}

/** Why a confirmation was not answered, among the reasons the screen names. */
const UNANSWERED = new Set(['NOT_ASKED', 'EXPIRED', 'ABANDONED', 'NO_CONFIRMATION']);

function unansweredWhy(reason: string | null): string {
  if (reason === null) {
    return 'NOT_ASKED';
  }
  return UNANSWERED.has(reason) ? reason : 'FAILED';
}

/** A request sent again as the live run or the stored record holds it; null without one. */
function resent(
  status: number | null | undefined,
  outcome: string | null | undefined,
  delivered: number | null | undefined,
  rule: string | null | undefined,
): AgentResent | null {
  if (status === null || status === undefined) {
    return null;
  }
  return {
    httpStatus: status,
    outcome: outcome ?? null,
    deliveredItems: delivered ?? 0,
    ruleId: rule ?? null,
  };
}

/** "처리됨 · HTTP 200 · 5건" or "거부됨 · HTTP 403"; the engine's rule code of a refusal waits in the fold. */
function resentWords(t: ReturnType<typeof useTranslation>['t'], value: AgentResent | null): string {
  if (value === null || value.httpStatus === null) {
    return t('main.6-4.notSent');
  }
  if (value.httpStatus >= 200 && value.httpStatus < 300) {
    return t('main.6-4.served', { status: value.httpStatus, items: value.deliveredItems });
  }
  return t('main.6-4.refused', { status: value.httpStatus });
}
