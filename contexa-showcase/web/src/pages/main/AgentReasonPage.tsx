import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { AGENT_CASE, useAgentCase, useAgentRun, useAgentTry, type AgentRunView } from '../../api/agentCase';
import { Term } from '../../components/common/Glossary';
import { Chip } from '../../components/main/Chip';
import { MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { CONTROL_ORDER } from '../../domain/verdict';
import { count } from '../../journey/format';
import {
  AGENT_PATHS,
  CONFIRMATION_RULE,
  existingAllPassed,
  firstStop,
  operationName,
  outcomeChip,
  periodWords,
  plusMinutes,
} from './agentGroup';
import { companyClock } from './mainCases';
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
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const agentCase = useAgentCase(AGENT_CASE);
  const tried = useAgentTry(AGENT_CASE);
  const ownReadable = tried.runId !== null && (tried.live === null || STORED.has(tried.live.status));
  const runId = ownReadable ? tried.runId : (agentCase.data?.recorded?.runId ?? null);
  const own = ownReadable;
  const record = useAgentRun(runId);
  const normal = useAgentRun(agentCase.data?.normalRecorded?.runId ?? null);
  const run = record.data ?? null;
  const delegation = agentCase.data?.delegation ?? null;
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
    <MainScreen title={t('main.6-3.title')} intro={pending ? null : intro}>
      {pending ? <StateScreen kind="loading" /> : null}
      {!pending && run === null ? (
        <p className={styles.note}>
          <Link to={AGENT_PATHS.request}>{t('main.6-2.toRequest')}</Link>
        </p>
      ) : null}
      {run && shown ? (
        <div className={styles.stack}>
          <p className={styles.subjectLine}>
            <Chip kind="auth">
              <Term term="delegatedAgent">{t('main.agent.subject')}</Term>
            </Chip>
            {own ? (
              <SourceBadge kind="run" runId={run.runId} step={shown.stepNo} />
            ) : (
              <SourceBadge kind="repeated" runs={1} runId={run.runId} step={shown.stepNo} />
            )}
          </p>
          <div className={styles.cards}>
            <section className={styles.card} aria-labelledby="fact-work">
              <h2 id="fact-work" className={styles.label}>
                <Term term="delegationRecord">{t('main.agent.work')}</Term>
              </h2>
              {delegation ? (
                <dl className={styles.rows}>
                  <div className={styles.row}>
                    <dt className={styles.rowName}>{t('main.agent.objective')}</dt>
                    <dd className={styles.rowValue}>{delegation.summary[language]}</dd>
                  </div>
                  <div className={styles.row}>
                    <dt className={styles.rowName}>
                      <Term term="delegationScope">{t('main.agent.scope')}</Term>
                    </dt>
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
                    <dt className={styles.rowName}>
                      <Term term="delegationPeriod">{t('main.agent.period')}</Term>
                    </dt>
                    <dd className={styles.rowValue}>
                      {periodWords(t, delegation)}
                      {ended ? ` · ${t('main.agent.endedAt', { at: companyClock(t, ended) })}` : ''}
                    </dd>
                  </div>
                </dl>
              ) : null}
            </section>
            <section className={styles.card} aria-labelledby="fact-request">
              <h2 id="fact-request" className={styles.label}>
                {t('main.6-3.request')}
              </h2>
              <dl className={styles.rows}>
                <div className={styles.row}>
                  <dt className={styles.rowName}>{t('main.6-3.step')}</dt>
                  <dd className={styles.rowValue}>
                    {t('main.6-2.step', { n: shown.stepNo })}
                    {shown.tool ? ` · ${shown.tool.tool}` : ''}
                  </dd>
                </div>
                <div className={styles.row}>
                  <dt className={styles.rowName}>{t('main.6-3.address')}</dt>
                  <dd className={styles.rowValue}>
                    <code className={styles.path}>{shown.path}</code>
                  </dd>
                </div>
                <div className={styles.row}>
                  <dt className={styles.rowName}>{t('main.6-3.at')}</dt>
                  <dd className={styles.rowValue}>{companyClock(t, shown.companyTime) ?? '-'}</dd>
                </div>
              </dl>
            </section>
            <section className={styles.card} data-mark aria-labelledby="fact-difference">
              <h2 id="fact-difference" className={styles.label}>
                {t('main.6-3.difference')}
              </h2>
              {trigger ? (
                <p className={styles.body}>
                  {i18n.exists(`main.agent.trigger.${trigger}`)
                    ? t(`main.agent.trigger.${trigger}`)
                    : trigger}
                  {trigger === 'DELEGATION_ENDED' && ended
                    ? ` ${t('main.6-3.endedVsAt', {
                        ended: companyClock(t, ended),
                        at: companyClock(t, shown.companyTime) ?? '-',
                      })}`
                    : ''}
                </p>
              ) : null}
              {action ? (
                <p className={styles.body}>
                  {t('main.6-3.decided', { action: t(`main.agent.action.${action}`) })}
                </p>
              ) : null}
              {!trigger && !action ? <p className={styles.body}>{t('main.6-3.noDifference')}</p> : null}
            </section>
          </div>
          <section className={styles.card} aria-labelledby="judgment">
            <h2 id="judgment" className={styles.label}>
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
