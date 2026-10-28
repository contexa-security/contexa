import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import {
  useAgentCase,
  useAgentCaseKey,
  useAgentRun,
  useAgentSubject,
  useAgentTry,
  type AgentRunView,
} from '../../api/agentCase';
import { useReferenceSnapshot } from '../../api/agentSnapshots';
import { Chip } from '../../components/main/Chip';
import { MainScreen } from '../../components/main/MainScreen';
import { SnapshotBadge } from '../../components/main/SnapshotBadge';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { Fold } from '../../components/main/Fold';
import { CONTROL_ORDER } from '../../domain/verdict';
import { count } from '../../journey/format';
import {
  AGENT_PATHS,
  CONFIRMATION_RULE,
  existingAllPassed,
  firstStop,
  outcomeChip,
  plusMinutes,
} from './agentGroup';
import { AgentChainLine, DelegationCompare } from './DelegationParts';
import { MeasureNote } from './MeasureNote';
import styles from './AgentPages.module.css';

/** The run states in which the agent's work is stored. */
const STORED = new Set(['CONFIRMING', 'COMPLETED']);

/**
 * 6-3, the delegation and the request, and the reasons (docs/agent 화면설계 4.3 AD-3, A7-3): three fact cards (the
 * work given, the request sent, and the difference the engine named), the judgment and its reasons, the four existing
 * approaches' results of the same request, and the legitimate pair (the same work within the delegation). The visitor's
 * own run is shown, else the latest operator recording of the case. "Only the delegation record showed it" is said
 * only when the run's records make it true: the four existing approaches let the request through, Contexa stopped it,
 * and its reason ties the delegation to the request (5-3's rule).
 */
export default function AgentReasonPage() {
  const { t, i18n } = useTranslation();
  const caseKey = useAgentCaseKey();
  const agentCase = useAgentCase(caseKey);
  const subject = useAgentSubject();
  const tried = useAgentTry(caseKey);
  const ownReadable = tried.runId !== null && (tried.live === null || STORED.has(tried.live.status));
  const runId = ownReadable ? tried.runId : (agentCase.data?.recorded?.runId ?? null);
  const own = ownReadable;
  const record = useAgentRun(runId);
  const normal = useAgentRun(agentCase.data?.normalRecorded?.runId ?? null);
  // AC-5: with no run of the visitor's and no recording of the case, a frozen real run stands in (no model is called).
  const snapshot = useReferenceSnapshot(
    runId === null && tried.live === null && !agentCase.isPending && !tried.pending,
  );
  const run = record.data ?? snapshot?.run ?? null;
  // the delegation this run executed (a visitor's copy of the editable case differs from the case's own), else the case's
  const delegation = run?.delegation ?? agentCase.data?.delegation ?? null;
  const stop = firstStop(run);
  const shown = stop ?? run?.steps[0] ?? null;
  const confirmation = run?.confirmation ?? null;
  const asked = stop?.outcomes.D?.rule === CONFIRMATION_RULE;
  // While the run waits for the delegating person the confirmation is stored only after the answer: the live view
  // holds its trigger until then.
  const liveTrigger = own ? (tried.live?.agentConfirmation?.trigger ?? null) : null;
  const trigger = asked ? (confirmation?.trigger ?? liveTrigger) : null;
  const action = stop?.decision?.final_action ?? null;
  const ended = delegation ? plusMinutes(run?.companyTime, delegation.validUntilMinutes) : null;
  const tied = trigger !== null || action !== null;
  const proof = stop !== null && existingAllPassed(stop) && tied;
  const pending = agentCase.isPending || tried.pending || (runId !== null && record.isPending);
  const intro =
    run === null
      ? t('main.6-3.intro.none')
      : stop === null
        ? t('main.6-3.intro.through')
        : proof
          ? t('main.6-3.intro.proof', { step: stop.stepNo })
          : t('main.6-3.intro.plain', { step: stop.stepNo });

  return (
    <MainScreen title={t('main.6-3.title')} intro={pending ? null : intro} subject={subject}>
      {pending ? <StateScreen kind="loading" /> : null}
      {!pending && run === null ? (
        <p className={styles.note}>
          <Link to={AGENT_PATHS.request}>{t('main.6-2.toRequest')}</Link>
        </p>
      ) : null}
      {run && shown ? (
        <div className={styles.stack}>
          <p className={styles.subjectLine}>
            {snapshot && record.data === undefined ? (
              <SnapshotBadge snapshot={snapshot} />
            ) : own ? (
              <SourceBadge kind="run" runId={run.runId} step={shown.stepNo} />
            ) : (
              <SourceBadge kind="repeated" runs={1} runId={run.runId} step={shown.stepNo} />
            )}
          </p>
          <div className={styles.cardsWide}>
            <section className={styles.card} data-mark aria-labelledby="fact-difference">
              <h2 id="fact-difference" className="visually-hidden">
                {t('main.6-3.difference')}
              </h2>
              {trigger ? (
                <p className={styles.body}>
                  {i18n.exists(`main.agent.trigger.${trigger}`)
                    ? t(`main.agent.trigger.${trigger}`)
                    : trigger}
                </p>
              ) : null}
              {action ? (
                <p className={styles.body}>
                  {t('main.6-3.decided', { action: t(`main.agent.action.${action}`) })}
                </p>
              ) : null}
              {!trigger && !action ? <p className={styles.body}>{t('main.6-3.noDifference')}</p> : null}
            </section>
            <section className={styles.card} aria-labelledby="judgment">
              <h2 id="judgment" className="visually-hidden">
                {t('main.6-3.judgment')}
              </h2>
              <p className={styles.body}>
                {stop === null
                  ? t('main.6-3.allThrough')
                  : asked
                    ? t('main.6-3.byRecord')
                    : action
                      ? t('main.6-3.byAi', {
                          calls: count(Number(stop.decision?.model_calls ?? 0), i18n.language),
                        })
                      : t('main.6-3.refused')}
              </p>
              {stop && action ? (
                <SourceBadge
                  kind={own ? 'run' : 'repeated'}
                  runs={1}
                  runId={run.runId}
                  step={stop.stepNo}
                  label={t('main.6-3.details')}
                />
              ) : null}
            </section>
          </div>
          {/* AC-N2: the difference the engine named and the judgment are the view; the two records side by side, the
              answers of the existing approaches and the normal pair are one press away. */}
          <Fold name="agent-compare" summary={t('main.6-3.compareFold')}>
            <AgentChainLine />
            {delegation ? (
              <DelegationCompare
                delegation={delegation}
                request={shown}
                runCompanyTime={run.companyTime}
                ended={ended}
              />
            ) : null}
            <section className={styles.card} aria-labelledby="existing">
              <h2 id="existing" className={styles.label}>
                {t('main.6-3.existing')}
              </h2>
              <ul className={styles.chips}>
                {CONTROL_ORDER.map((control) => {
                  const result = shown.outcomes[control];
                  const chip = outcomeChip(result?.outcome, result?.rule);
                  return (
                    <li key={control} className={styles.chipItem}>
                      <span className={styles.chipName}>{t(`control.${control}.name`)}</span>
                      <Chip kind={chip.kind}>
                        {i18n.exists(`main.agent.outcome.${chip.word}`)
                          ? t(`main.agent.outcome.${chip.word}`)
                          : chip.word}
                      </Chip>
                    </li>
                  );
                })}
              </ul>
            </section>
            <NormalPair run={normal.data ?? null} pairKey={agentCase.data?.normalPair ?? null} />
            <MeasureNote own={own} stopReason={run.stopReason} />
          </Fold>
        </div>
      ) : null}
    </MainScreen>
  );
}

/** The same work given within the delegation period: its operator recording, as the five approaches handled it. */
function NormalPair({
  run,
  pairKey,
}: {
  readonly run: AgentRunView | null;
  readonly pairKey: string | null;
}) {
  const { t, i18n } = useTranslation();
  if (run === null || pairKey === null) {
    return null;
  }
  const requests = run.steps.length;
  const delivered = run.steps.filter((step) => step.outcomes.D?.outcome === 'DELIVERED').length;
  const existing = run.steps.filter((step) => existingAllPassed(step)).length;
  return (
    <section className={styles.card} aria-labelledby="normal-pair">
      <h2 id="normal-pair" className={styles.label}>
        {t('main.6-3.pair', { key: pairKey })}
      </h2>
      <p className={styles.body}>
        {t('main.6-3.pairLine', {
          requests: count(requests, i18n.language),
          existing: count(existing, i18n.language),
          delivered: count(delivered, i18n.language),
        })}
      </p>
      <p className={styles.body}>{t(run.finalAnswer ? 'main.6-3.pairDone' : 'main.6-3.pairNotDone')}</p>
      <SourceBadge kind="repeated" runs={1} runId={run.runId} step={1} />
    </section>
  );
}
