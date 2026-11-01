import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom';
import { NO_CHOICE, useAgentCase, useAgentRun, useDelegationChoice, type DelegationChoice } from '../../../../api/agentCase';
import { REFERENCE_SNAPSHOT, useAgentSnapshot } from '../../../../api/agentSnapshots';
import { postJson } from '../../../../api/http';
import { useJourneyUpdate } from '../../../../api/journey';
import { useLiveConfig } from '../../../../api/queries';
import type { LiveRunView } from '../../../../api/types';
import { useLiveSend } from '../../../../hooks/useLiveSend';
import { formatNumber } from '../../../format';
import {
  AGENT_MAIN,
  agentPath,
  chainResource,
  rememberCall,
  rememberedCall,
  useAgentCases,
} from '../../../simulate/agent';
import { CaseFacts, DelegationChain, DelegationFacts, Instruction } from '../../../simulate/AgentParts';
import { FlowSteps } from '../../../simulate/FlowFrame';
import { companyClock, truthOf } from '../../../simulate/person';
import { useAgentRuns } from '../../../simulate/useFlow';
import { Badge, Button, ButtonLink, CodeChip, Icon, Loading, Note, PageHead } from '../../../ui';
import review from '../../../simulate/Review.module.css';
import styles from '../../../simulate/Agent.module.css';

type Call = 'ALLOW' | 'BLOCK';

/** The experience the portal scores the agent group's call under; it binds the main case only (DEC-35). */
const AGENT_EXPERIENCE = 'E4';

/**
 * Step 2 of the agent delegation flow (기획안 7.6 · s-agent): the delegation the company recorded — who delegated what
 * to which agent, its scope and period with the agent's request on the line — and the instruction word for word,
 * beside the visitor's expected decision and the run. A case the portal does not open leads back to step 1 (DEC-27).
 */
export default function AgentReviewPage() {
  const { caseKey } = useParams();
  const cases = useAgentCases();
  if (cases.pending) {
    return (
      <>
        <FlowSteps current="review" />
        <Loading rows={6} />
      </>
    );
  }
  if (!caseKey || !cases.opens(caseKey)) {
    return <Navigate replace to="/simulate/agent" />;
  }
  return <Review caseKey={caseKey} />;
}

/** The changed values of the delegation the address names (ST-31), in the delegation's own words. */
function changedOf(choice: DelegationChoice): ('quantity' | 'period' | 'operations')[] {
  return (['quantity', 'period', 'operations'] as const).filter((what) => choice[what] !== null);
}

function Review({ caseKey }: { readonly caseKey: string }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const choice = useDelegationChoice(caseKey);
  const changed = changedOf(choice);
  const agentCase = useAgentCase(caseKey, changed.length > 0 ? choice : NO_CHOICE);
  const config = useLiveConfig();
  const runs = useAgentRuns();
  const saveJourney = useJourneyUpdate();
  const snapshot = useAgentSnapshot(caseKey === AGENT_MAIN ? REFERENCE_SNAPSHOT : null);
  const scored = caseKey === AGENT_MAIN;
  const earlier = scored
    ? (runs.predictions.find((prediction) => prediction.experience === AGENT_EXPERIENCE)?.call.engine ?? null)
    : rememberedCall(caseKey);
  const [call, setCall] = useState<Call | null>(null);
  const chosen: Call | null = call ?? (earlier === null ? null : earlier === 'ALLOW' ? 'ALLOW' : 'BLOCK');
  const post =
    changed.length > 0
      ? (turnstileToken: string | null) =>
          postJson<LiveRunView & { reason?: string }>('/api/live/runs', {
            scenario: caseKey,
            turnstileToken,
            delegation: choice,
          })
      : undefined;
  const { send, sending, ready, refusal, reason, waiting, turnstileContainer, turnstileRequired } = useLiveSend(
    caseKey,
    () => navigate(agentPath(caseKey, 'live', changed.length > 0 ? window.location.search : '')),
    post ? { post } : {},
  );
  const n = (value: number) => formatNumber(value, i18n.language);
  const data = agentCase.data ?? null;
  // The requests of the case's latest operator recording, with the company time each went at (옛 6-1).
  const recent = useAgentRun(data?.recorded?.runId ?? null).data ?? null;
  const truth = truthOf(data?.classification);
  const agentsLeft = config.data?.remainingAgentToday ?? null;
  const ticketsLeft = config.data?.liveTicketsLeft ?? null;
  const recorded = data?.recorded?.runId ?? snapshot.data?.runId ?? null;
  const visitorReady = runs.visitorReady;
  const reasonText = !visitorReady
    ? t('ux.review.reason.visitor')
    : agentsLeft === 0
      ? t('ux.agentReview.reason.agentLimit')
      : ticketsLeft !== null && ticketsLeft <= 0
        ? t('ux.agentReview.reason.tickets')
        : chosen === null
          ? t('ux.review.reason.predict')
          : turnstileRequired && !ready && !sending && !waiting
            ? t('ux.review.reason.human')
            : undefined;
  const refusalText =
    refusal === 'dailyLimit' && (reason === 'AGENT_LIMIT' || agentsLeft === 0)
      ? t('ux.agentReview.refusal.agentLimit')
      : refusal
        ? t(`ux.review.refusal.${refusal}`)
        : null;

  if (agentCase.isPending) {
    return (
      <>
        <FlowSteps current="review" />
        <Loading rows={6} />
      </>
    );
  }
  if (!data) {
    return (
      <>
        <FlowSteps current="review" />
        <Note tone="warn">{t('ux.agentReview.unavailable')}</Note>
      </>
    );
  }
  return (
    <>
      <FlowSteps current="review" />
      <PageHead
        kicker={
          <>
            <Badge tone="line" icon="bot">
              {t('ux.menu.agent')}
            </Badge>
            <CodeChip value={caseKey} />
            <CaseFacts sender={data.sender} recorded={data.recorded} />
            <span className={review.truth}>
              {t(`ux.flow.truth.${truth}`)} · {t('ux.flow.truthHidden')}
            </span>
          </>
        }
        title={data.title[language] ?? caseKey}
        desc={t('ux.agentReview.desc')}
        actions={
          <ButtonLink to={caseKey === config.data?.delegationEdit?.case ? '/simulate/policy?tab=agent' : '/simulate/agent'} variant="text">
            {t('ux.flow.changeScenario')}
          </ButtonLink>
        }
      />
      <div className={styles.review}>
        <section className={styles.reviewMain} aria-label={t('ux.agentReview.delegationLabel')}>
          <DelegationChain
            delegator={t(`ux.person.${data.protagonist}`, { defaultValue: data.protagonist })}
            agent={data.agentTitle[language] ?? data.agentName}
            resource={chainResource(data.delegation)}
          />
          <DelegationFacts delegation={data.delegation} changed={changed} />
          <Instruction
            text={data.instruction[language] ?? data.instruction.en ?? ''}
            label={t('ux.agentReview.instruction')}
          />
          {recent && recent.steps.length > 0 ? (
            <details className={styles.more}>
              <summary>{t('ux.agentReview.recent')}</summary>
              <ol className={styles.moreList}>
                {recent.steps.map((step) => (
                  <li key={step.stepNo}>
                    <span className={styles.requestNo}>{t('ux.pick.requestNo', { n: step.stepNo })}</span>{' '}
                    {companyClock(t, step.companyTime)} <code className={styles.morePath}>{step.path}</code>
                  </li>
                ))}
              </ol>
            </details>
          ) : null}
          {truth === 'undetermined' ? <Note>{t('ux.agentReview.unscored')}</Note> : null}
        </section>

        <section className={styles.reviewSide} aria-labelledby="predict-title">
          <div className={review.predictHead}>
            <h2 id="predict-title" className={review.predictTitle}>
              {t('ux.review.predict.title')}
            </h2>
            <p className={review.predictDesc}>{t('ux.review.predict.desc')}</p>
          </div>
          <div role="radiogroup" aria-labelledby="predict-title" className={review.choices}>
            {(['ALLOW', 'BLOCK'] as const).map((option) => (
              <button
                key={option}
                type="button"
                role="radio"
                aria-checked={chosen === option}
                className={review.choice}
                onClick={() => setCall(option)}
              >
                <span className={review.choiceIcon} data-tone={option === 'ALLOW' ? 'allow' : 'block'}>
                  <Icon name={option === 'ALLOW' ? 'check' : 'user-round-check'} size="xl" />
                </span>
                <span className={review.choiceText}>
                  <b>{t(`ux.agentReview.predict.${option}.title`)}</b>
                  <span>{t(`ux.agentReview.predict.${option}.desc`)}</span>
                </span>
                <span className={review.radio} aria-hidden="true" />
              </button>
            ))}
          </div>
          {turnstileRequired ? <div ref={turnstileContainer} className={review.turnstile} /> : null}
          <div className={styles.runButton}>
            <Button
              variant="primary"
              size="lg"
              icon="play"
              busy={sending || waiting}
              {...(reasonText ? { disabledReason: reasonText } : {})}
              onClick={() =>
                void send(async () => {
                  if (!chosen) {
                    return;
                  }
                  if (scored) {
                    await saveJourney({ prediction: { experience: AGENT_EXPERIENCE, engine: chosen } });
                  } else {
                    rememberCall(caseKey, chosen);
                  }
                })
              }
            >
              {t('ux.agentReview.run')}
            </Button>
          </div>
          <ul className={styles.sideMeta}>
            <li>{t('ux.agentReview.realAgent')}</li>
            {config.data?.dailyAgentRuns != null && agentsLeft !== null ? (
              <li>
                {t('ux.agentReview.daily', { n: n(config.data.dailyAgentRuns), left: n(agentsLeft) })}
              </li>
            ) : null}
          </ul>
          {ticketsLeft !== null ? (
            <details className={styles.more}>
              <summary>{t('ux.agent.more')}</summary>
              <p className={styles.moreText}>{t('ux.agentReview.tickets', { n: n(ticketsLeft) })}</p>
            </details>
          ) : null}
        </section>
      </div>
      {waiting ? <Note icon="hourglass">{t('ux.review.waiting')}</Note> : null}
      {refusalText ? (
        <div className={review.refusal} role="alert">
          <Note tone="warn">{refusalText}</Note>
          {recorded && refusal !== 'turnstile' ? (
            <Link to={`/runs/${encodeURIComponent(recorded)}`} className={review.recordedLink}>
              {t('ux.review.recorded')}
            </Link>
          ) : null}
        </div>
      ) : null}
    </>
  );
}
