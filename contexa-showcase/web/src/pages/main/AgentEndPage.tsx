import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import {
  AGENT_CASE,
  useAgentSubject,
  type AgentResent,
  type AgentRunConfirmation,
} from '../../api/agentCase';
import { useAgentSnapshot, type AgentSnapshot } from '../../api/agentSnapshots';
import { Chip } from '../../components/main/Chip';
import { MainScreen } from '../../components/main/MainScreen';
import { SnapshotBadge } from '../../components/main/SnapshotBadge';
import { StateScreen } from '../../components/StateScreen';
import { Fold } from '../../components/main/Fold';
import { AGENT_PATHS, outcomeChip } from './agentGroup';
import { AgentChainLine } from './DelegationParts';
import styles from './AgentEndPage.module.css';

/** The two stored runs of the case, by what the delegating person answered. */
const ANSWERS = [
  { decision: 'APPROVE', label: 'T5-confirm-approve' },
  { decision: 'REPORT', label: 'T5-confirm-report' },
] as const;

/**
 * 6-5, what the delegating person's answer changes (docs/agent Agent중심-화면 AS-7): a request outside the delegation's
 * period is held for the person; this screen sets two stored real runs of it side by side, the answer approve and the
 * answer report. An approval lets that one request through once; a report refuses it and stops the agent at once (its
 * delegation revoked), so its next request is refused at sign-in. Both are the portal's stored records, read as files:
 * nothing is run for the visitor, no model is called, whatever the database holds.
 */
export default function AgentEndPage() {
  const { t } = useTranslation();
  const subject = useAgentSubject();
  const approve = useAgentSnapshot(ANSWERS[0].label);
  const report = useAgentSnapshot(ANSWERS[1].label);
  const loaded: readonly (AgentSnapshot | undefined)[] = [approve.data, report.data];
  const pending = approve.isPending || report.isPending;
  const missing = !pending && loaded.some((snapshot) => snapshot === undefined);

  return (
    <MainScreen title={t('main.6-5.title')} intro={t('main.6-5.intro')} subject={subject}>
      {pending ? <StateScreen kind="loading" /> : null}
      {missing ? (
        <p className={styles.note}>
          <Link to={AGENT_PATHS.reason}>{t('main.6-5.toReason')}</Link>
        </p>
      ) : null}
      {!pending && !missing ? (
        <div className={styles.stack}>
          <AgentChainLine />
          <div className={styles.columns}>
            {ANSWERS.map((answer, index) => {
              const snapshot = loaded[index] as AgentSnapshot;
              return <Column key={answer.decision} decision={answer.decision} snapshot={snapshot} />;
            })}
          </div>
          <p className={styles.note}>{t('main.6-5.limit', { key: AGENT_CASE })}</p>
        </div>
      ) : null}
    </MainScreen>
  );
}

function Column({
  decision,
  snapshot,
}: {
  readonly decision: 'APPROVE' | 'REPORT';
  readonly snapshot: AgentSnapshot;
}) {
  const { t } = useTranslation();
  const confirmation: AgentRunConfirmation | null = snapshot.run.confirmation;
  return (
    <section className={styles.column} aria-labelledby={`end-${decision}`}>
      <h2 id={`end-${decision}`} className={styles.heading}>
        {t(`main.6-5.column.${decision}`)}
      </h2>
      <p className={styles.explain}>{t(`main.6-5.say.${decision}`)}</p>
      {/* AC-N2: the conclusion of the answer is the view; the run's stored mark and its rows wait under one line. */}
      <Fold name="end-record" summary={t('main.6-5.recordFold')}>
        <p className={styles.explain}>{t(`main.6-5.more.${decision}`)}</p>
        <SnapshotBadge snapshot={snapshot} />
        <dl className={styles.rows}>
          <Row name={t('main.6-5.row.answer')}>
            <b>{t(`main.6-5.answer.${decision}`)}</b>
          </Row>
          <Row name={t('main.6-5.row.after')}>
            {confirmation?.after?.status ? (
              <b>
                {t(`main.6-5.status.${confirmation.after.status}`, {
                  defaultValue: confirmation.after.status,
                })}
              </b>
            ) : (
              <span>{t('main.6-5.noStatus')}</span>
            )}
          </Row>
          <Row name={t('main.6-5.row.resend')}>
            <Sent sent={confirmation?.resend ?? null} />
          </Row>
          <Row name={t('main.6-5.row.reuse')}>
            <Sent sent={confirmation?.reuse ?? null} />
          </Row>
          <Row name={t('main.6-5.row.other')}>
            <Sent sent={confirmation?.other ?? null} />
          </Row>
        </dl>
      </Fold>
    </section>
  );
}

function Row({ name, children }: { readonly name: string; readonly children: React.ReactNode }) {
  return (
    <div className={styles.row}>
      <dt>{name}</dt>
      <dd>{children}</dd>
    </div>
  );
}

/** A request sent again, as the stored record holds it; "not sent" when the answer did not lead to one. */
function Sent({ sent }: { readonly sent: AgentResent | null }) {
  const { t, i18n } = useTranslation();
  if (sent === null || sent.outcome === null) {
    return <span>{t('main.6-5.notSent')}</span>;
  }
  const chip = outcomeChip(sent.outcome, sent.ruleId);
  return (
    <span className={styles.sent}>
      <Chip kind={chip.kind}>
        {i18n.exists(`main.agent.outcome.${chip.word}`) ? t(`main.agent.outcome.${chip.word}`) : chip.word}
      </Chip>
      {sent.httpStatus !== null ? <span>{t('main.6-5.http', { status: sent.httpStatus })}</span> : null}
    </span>
  );
}
