import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import {
  useAgentCase,
  useAgentCaseKey,
  useAgentRun,
  useAgentSubject,
  useAgentTry,
  type AgentProof,
  type AgentRunView,
} from '../../api/agentCase';
import { useReferenceSnapshot } from '../../api/agentSnapshots';
import { MainScreen } from '../../components/main/MainScreen';
import { SnapshotBadge } from '../../components/main/SnapshotBadge';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { CONTROL_ORDER } from '../../domain/verdict';
import { AGENT_PATHS } from './agentGroup';
import { AgentChainLine } from './DelegationParts';
import { ResultLanes, ResultSummary } from './AgentResultParts';
import { MeasureNote } from './MeasureNote';
import styles from './AgentResultPage.module.css';

/** The run states in which the agent's work is stored. */
const STORED = new Set(['CONFIRMING', 'COMPLETED']);

/**
 * 6-7, the agent's result on one page (docs/agent Agent중심-화면 AS-8): the requests it sent, what its work needs, the
 * first request that was stopped and what went to the delegating person, then the five approaches as lanes, in the
 * layout of the people's result screen. Every number is the portal's scoring of the run (the proof), never a count the
 * screen made. The visitor's own run is shown; without one, the frozen reference run (a real, stored run) stands in and
 * the screen says so.
 */
export default function AgentResultPage() {
  const { t, i18n } = useTranslation();
  const caseKey = useAgentCaseKey();
  const agentCase = useAgentCase(caseKey);
  const subject = useAgentSubject();
  const tried = useAgentTry(caseKey);
  const ownReadable = tried.runId !== null && (tried.live === null || STORED.has(tried.live.status));
  const own = useAgentRun(ownReadable ? tried.runId : null);
  const snapshot = useReferenceSnapshot(!ownReadable && !tried.pending && !agentCase.isPending);
  const run: AgentRunView | null = own.data ?? snapshot?.run ?? null;
  const proof = run?.proof ?? null;
  const pending = tried.pending || (ownReadable && own.isPending);

  return (
    <MainScreen
      title={proof ? headline(t, proof) : t('main.6-7.title.none')}
      intro={proof ? t('main.6-7.intro') : null}
      subject={subject}
      extra={
        <Link to="/benchmark/agent" className={styles.benchLink}>
          {t('main.6-7.bench')}
        </Link>
      }
    >
      {pending ? <StateScreen kind="loading" /> : null}
      {!pending && (run === null || proof === null) ? (
        <p className={styles.note}>
          <Link to={AGENT_PATHS.request}>{t('main.6-2.toRequest')}</Link>
        </p>
      ) : null}
      {run && proof ? (
        <div className={styles.stack}>
          <AgentChainLine />
          <p className={styles.badges}>
            {own.data && tried.runId ? (
              <SourceBadge kind="run" runId={tried.runId} />
            ) : snapshot ? (
              <SnapshotBadge snapshot={snapshot} />
            ) : null}
          </p>
          <ResultSummary run={run} proof={proof} language={i18n.language} />
          <ResultLanes proof={proof} language={i18n.language} />
          <MeasureNote own={own.data !== undefined} stopReason={run.stopReason} />
        </div>
      ) : null}
    </MainScreen>
  );
}

/** The one sentence the result stands on: where control D stopped the work, and how many of the others did not. */
function headline(t: ReturnType<typeof useTranslation>['t'], proof: AgentProof): string {
  const d = proof.controls['D'];
  const others = CONTROL_ORDER.filter((control) => control !== 'D');
  const neverStopped = others.filter((control) => proof.controls[control]?.firstStopStep == null).length;
  if (d?.firstStopStep != null) {
    return t('main.6-7.title.stopped', { step: d.firstStopStep, others: neverStopped });
  }
  const first = others
    .map((control) => proof.controls[control]?.firstStopStep ?? null)
    .filter((step): step is number => step !== null);
  if (first.length > 0) {
    return t('main.6-7.title.othersStopped', { step: Math.min(...first) });
  }
  return t('main.6-7.title.through', { sent: proof.sent });
}
