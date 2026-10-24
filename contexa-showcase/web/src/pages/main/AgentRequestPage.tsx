import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { AGENT_CASE, useAgentCase, useAgentRun } from '../../api/agentCase';
import { useJourneyUpdate, type EngineCall } from '../../api/journey';
import { Term } from '../../components/common/Glossary';
import { GuidePreview } from '../../components/guide/GuidePreview';
import { MainButton, MainScreen } from '../../components/main/MainScreen';
import { StateScreen } from '../../components/StateScreen';
import { useLiveSend } from '../../hooks/useLiveSend';
import { AGENT_EXPERIENCE, AGENT_PATHS, operationName, periodWords } from './agentGroup';
import { companyClock } from './mainCases';
import styles from './AgentPages.module.css';

/** The visitor's call before the agent sends (설계서 4.3 AD-1): does the agent's request go through? */
const CALLS: readonly EngineCall[] = ['ALLOW', 'BLOCK'];

/**
 * 6-1, giving the agent the work (docs/agent 화면설계 4.3 AD-1, A7-3): the work the employee gave the business agent
 * and its delegation as the case records them, what the employee asked the agent, where the agent's requests come
 * from (the agent decides them itself), the visitor's call and the send. The requests are the agent's own, so the
 * screen does not list or mark them; the difference is the engine's to name (6-3).
 */
export default function AgentRequestPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const navigate = useNavigate();
  const update = useJourneyUpdate();
  const agentCase = useAgentCase(AGENT_CASE);
  const [call, setCall] = useState<EngineCall | null>(null);
  const {
    send: sendRun,
    sending,
    ready,
    refusal,
    waiting,
    turnstileContainer,
    turnstileRequired,
  } = useLiveSend(AGENT_CASE, () => {
    void navigate(AGENT_PATHS.console);
  });
  const found = agentCase.data ?? null;
  // 설계서 4.3 AD-1: the requests of the latest recorded run of the same case, without their outcomes.
  const recent = useAgentRun(found?.recorded?.runId ?? null);
  const delegation = found?.delegation ?? null;

  function send() {
    if (call === null) {
      return;
    }
    const picked = call;
    void sendRun(async () => {
      await update({ prediction: { experience: AGENT_EXPERIENCE, engine: picked } });
    });
  }

  return (
    <MainScreen
      title={t('main.6-1.title')}
      intro={t('main.6-1.intro')}
      // docs/agent A7-4: the guide to the agent group, before the visitor gives the agent the work.
      guide={<GuidePreview id="agent" />}
      nextNote={found && call === null ? t('main.request.pickFirst') : undefined}
      main={
        <MainButton onClick={send} disabled={!ready || call === null}>
          {t(sending ? 'main.request.sending' : 'main.6-1.send')}
        </MainButton>
      }
    >
      {agentCase.isPending ? <StateScreen kind="loading" /> : null}
      {agentCase.isError ? <StateScreen kind="notReady" /> : null}
      {found ? (
        <div className={styles.layout}>
          <section className={styles.card} aria-labelledby="agent-work">
            <h2 id="agent-work" className={styles.label}>
              <Term term="delegationRecord">{t('main.agent.work')}</Term>
            </h2>
            <dl className={styles.rows}>
              <div className={styles.row}>
                <dt className={styles.rowName}>
                  <Term term="delegator">{t('main.agent.delegator')}</Term>
                </dt>
                <dd className={styles.rowValue}>
                  {t(`person.${found.protagonist}`, { defaultValue: found.protagonist })}
                </dd>
              </div>
              <div className={styles.row}>
                <dt className={styles.rowName}>
                  <Term term="businessAgent">{t('main.agent.agent')}</Term>
                </dt>
                <dd className={styles.rowValue}>{found.agentTitle[language]}</dd>
              </div>
              {delegation ? (
                <>
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
                    <dd className={styles.rowValue}>{periodWords(t, delegation)}</dd>
                  </div>
                </>
              ) : null}
            </dl>
            <p className={styles.caseKey}>{t('main.request.caseKey', { key: AGENT_CASE })}</p>
          </section>
          <div className={styles.side}>
            <section className={styles.card} aria-labelledby="agent-asked">
              <h2 id="agent-asked" className={styles.label}>
                {t('main.6-1.asked')}
              </h2>
              <p className={styles.quote}>{found.instruction[language]}</p>
              <p className={styles.note}>{t('main.6-1.source')}</p>
            </section>
            <section className={styles.card} aria-labelledby="agent-recent">
              <h2 id="agent-recent" className={styles.label}>
                {t('main.6-1.recent')}
              </h2>
              {recent.data && recent.data.steps.length > 0 ? (
                <ul className={styles.recentList}>
                  {recent.data.steps.map((step) => (
                    <li key={step.stepNo}>
                      {t('main.6-1.recentRow', {
                        at: companyClock(t, step.companyTime) ?? '-',
                        path: step.path,
                      })}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className={styles.note}>{t('main.6-1.recentNone')}</p>
              )}
            </section>
            <fieldset className={styles.predict}>
              <legend className={styles.label}>{t('main.6-1.predict')}</legend>
              {CALLS.map((choice) => (
                <label key={choice} className={styles.choice} data-selected={call === choice || undefined}>
                  <input
                    type="radio"
                    name="call"
                    className="visually-hidden"
                    checked={call === choice}
                    onChange={() => setCall(choice)}
                  />
                  <b className={styles.choiceName}>{t(`main.6-1.call.${choice}`)}</b>
                  <span className={styles.choiceHint}>{t(`main.6-1.call.${choice}.hint`)}</span>
                </label>
              ))}
              <p className={styles.note}>{t('main.request.noAnswer')}</p>
            </fieldset>
          </div>
        </div>
      ) : null}
      {turnstileRequired ? <div ref={turnstileContainer} /> : null}
      {waiting ? <p className={styles.note}>{t('p1.predict.waitEarlier')}</p> : null}
      {refusal ? (
        <StateScreen
          kind={refusal === 'dailyLimit' ? 'dailyLimit' : refusal === 'paused' ? 'paused' : 'outage'}
          // The case is not a replayed scenario: its operator recording is shown on 6-3.
          recordTo={AGENT_PATHS.reason}
          {...(refusal === 'error' || refusal === 'turnstile' ? { onRetry: send } : {})}
        />
      ) : null}
    </MainScreen>
  );
}
