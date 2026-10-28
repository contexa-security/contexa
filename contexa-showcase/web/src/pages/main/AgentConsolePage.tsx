import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useAgentCaseKey, useAgentRun, useAgentSubject, useAgentTry, type AgentRunStep } from '../../api/agentCase';
import type { LiveLayer } from '../../api/types';
import { Term } from '../../components/common/Glossary';
import { MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import { AGENT_PATHS, CONFIRMATION_RULE, layersOf } from './agentGroup';
import { AgentChainLine } from './DelegationParts';
import { AgentTimeline } from './AgentTimeline';
import { MeasureNote } from './MeasureNote';
import styles from './AgentPages.module.css';

/** The run states during which the console still follows the agent's work. */
const WORKING = new Set(['QUEUED', 'STARTING', 'RUNNING']);
/** The run states in which the agent's work is stored and its record can be read. */
const STORED = new Set(['CONFIRMING', 'COMPLETED']);

interface Row {
  readonly stepNo: number;
  readonly layers: Readonly<Record<string, LiveLayer>>;
  readonly step: AgentRunStep | null;
}

/**
 * 6-2, the live decision console of the agent's work (docs/agent 화면설계 4.3 AD-2, A7-3): every request the agent
 * sent, one row each, with each of the five approaches' answers as they arrive; once the work is stored, the tool that
 * sent each request, its address and Contexa's decision. When control D asked the delegating person to confirm, the
 * line says so and leads to 6-4. Every value is the run's own record.
 */
export default function AgentConsolePage() {
  const { t, i18n } = useTranslation();
  const tried = useAgentTry(useAgentCaseKey());
  const subject = useAgentSubject();
  const live = tried.live;
  const status = live?.status ?? null;
  const readable = tried.runId !== null && (live === null || STORED.has(status ?? ''));
  const record = useAgentRun(readable ? tried.runId : null);
  const run = record.data ?? null;
  const working = status !== null && WORKING.has(status);
  const confirming = status === 'CONFIRMING';
  const rows: readonly Row[] = run
    ? run.steps.map((step) => ({ stepNo: step.stepNo, layers: layersOf(step), step }))
    : (live?.steps ?? []).map((step) => ({ stepNo: step.stepNo, layers: step.layers, step: null }));
  const asked = rows.some((row) => row.layers.D?.ruleId === CONFIRMATION_RULE);
  const trigger = live?.agentConfirmation?.trigger ?? run?.confirmation?.trigger ?? null;
  const decided = run?.steps.filter((step) => step.decision?.final_action) ?? [];
  const decisionCalls = (run?.cost.decisions ?? []).reduce((sum, model) => sum + Number(model.calls ?? 0), 0);
  const agentTokens = Number(run?.cost.agent.totalTokens ?? 0);
  const unsent = !tried.pending && tried.runId === null && live === null;

  return (
    <MainScreen
      subject={subject}
      title={t('main.6-2.title')}
      intro={unsent ? t('main.6-2.intro.none') : t('main.6-2.intro')}
      live={live && (working || confirming) ? live.liveRunId : null}
      waiting={working ? { label: t('main.6-2.waiting'), hint: t('main.6-2.waitingHint') } : null}
    >
      {tried.pending ? <StateScreen kind="loading" /> : null}
      {unsent ? (
        <p className={styles.note}>
          <Link to={AGENT_PATHS.request}>{t('main.6-2.toRequest')}</Link>
        </p>
      ) : null}
      {!unsent && !tried.pending ? (
        <div className={styles.stack}>
          <AgentChainLine />
          {tried.runId ? (
            <p className={styles.subjectLine}>
              <SourceBadge kind="run" runId={tried.runId} />
            </p>
          ) : null}
          <MeasureNote own={tried.own} stopReason={run?.stopReason ?? null} />
          <AgentTimeline rows={rows} />
          <p className={styles.note}>{t('main.6-2.legend')}</p>
          {working && rows.length === 0 ? <p className={styles.note}>{t('main.6-2.working')}</p> : null}
          {asked ? (
            <section className={styles.callout} aria-labelledby="agent-asked-line">
              <h2 id="agent-asked-line" className={styles.label}>
                <Term term="delegatorCheck">{t('main.6-2.confirmAsked')}</Term>
              </h2>
              {trigger && i18n.exists(`main.agent.trigger.${trigger}`) ? (
                <p className={styles.body}>{t(`main.agent.trigger.${trigger}`)}</p>
              ) : null}
              <p className={styles.body}>
                {confirming ? (
                  <Link to={AGENT_PATHS.confirm}>{t('main.6-2.toConfirm')}</Link>
                ) : (
                  t('main.6-2.confirmLater')
                )}
              </p>
            </section>
          ) : null}
          {run ? (
            <section className={styles.card} aria-labelledby="agent-analysis">
              <h2 id="agent-analysis" className={styles.label}>
                {t('main.6-2.analysis')}
              </h2>
              <p className={styles.body}>
                {decided.length === 0
                  ? t('main.6-2.noAnalysis')
                  : t('main.6-2.analysed', {
                      n: decided.length,
                      actions: decided
                        .map(
                          (step) =>
                            `${t('main.6-2.step', { n: step.stepNo })} ${t(`main.agent.action.${step.decision?.final_action}`)}`,
                        )
                        .join(', '),
                    })}
              </p>
              <p className={styles.note}>
                {t('main.6-2.cost', {
                  tokens: count(agentTokens, i18n.language),
                  calls: count(decisionCalls, i18n.language),
                })}
              </p>
            </section>
          ) : null}
          {run?.finalAnswer ? (
            <section className={styles.card} aria-labelledby="agent-answer">
              <h2 id="agent-answer" className={styles.label}>
                {t('main.6-2.answer')}
              </h2>
              <p className={styles.quote}>{run.finalAnswer}</p>
              <p className={styles.note}>{t('main.agent.agentWrote')}</p>
            </section>
          ) : null}
          {status === 'FAILED' ? <StateScreen kind="outage" /> : null}
        </div>
      ) : null}
    </MainScreen>
  );
}
