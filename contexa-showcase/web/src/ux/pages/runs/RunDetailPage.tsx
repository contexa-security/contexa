import { useTranslation } from 'react-i18next';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { NO_CHOICE, useAgentCase, useAgentRun } from '../../../api/agentCase';
import { useAnatomy } from '../../../api/anatomy';
import { HttpError } from '../../../api/http';
import { useRunScore } from '../../../api/queries';
import { subjectOfSender } from '../../../domain/subject';
import { formatDuration, formatNumber, formatUtc } from '../../format';
import { decisionOf, useScenarioTitle } from '../../runs/runLog';
import { agentPath, useAgentCases } from '../../simulate/agent';
import { PERSON_KEYS, evalOf, flowPath, verdictOf, type PersonKey } from '../../simulate/person';
import {
  Badge,
  ButtonLink,
  CodeChip,
  ErrorState,
  EvalBadge,
  Loading,
  PageHead,
  SummaryBar,
  TabPanel,
  Tabs,
  VerdictBadge,
} from '../../ui';
import {
  ControlsTab,
  EvidenceTab,
  IntegrityTab,
  LearningTab,
  PromptTab,
  ResponseTab,
  SummaryTab,
} from './detailTabs';
import { noDecisionKey } from './detailWords';
import styles from './Detail.module.css';

const TABS = ['summary', 'controls', 'evidence', 'prompt', 'response', 'integrity', 'learning'] as const;
type TabId = (typeof TABS)[number];

/**
 * The decision details (기획안 7.3, DEC-42): one run's request as a page of seven tabs — the summary, each control's
 * answer, the evidence, the prompt, the model's original answer, the integrity check and the baseline learning. The
 * request (`?step=`) and the tab (`?tab=`) live in the address, so the page can be shared and cited. A run of several
 * requests moves between them without leaving the tab (ST-45).
 */
export default function RunDetailPage() {
  const { runId = '' } = useParams();
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const score = useRunScore(runId, 'detail', 1);
  const steps = score.data?.executedSteps ?? 1;
  const asked = Math.floor(Number(params.get('step')) || 0);
  const step = Math.min(Math.max(asked || (score.data ? decisionOf(score.data).step : 1), 1), Math.max(steps, 1));
  const tab: TabId = TABS.includes(params.get('tab') as TabId) ? (params.get('tab') as TabId) : 'summary';
  const anatomy = useAnatomy(runId, step);
  const agent = useAgentRun(runId);
  const caseKey = score.data?.scenarioKey ?? null;
  // An agent run's case: its operator recordings are counted by the portal (AS-5), shown where the case is named.
  const agentCase = useAgentCase(caseKey ?? '', NO_CHOICE, Boolean(agent.data && caseKey));
  const cases = useAgentCases();
  const titleOf = useScenarioTitle();
  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    next.set(key, value);
    setParams(next, { replace: true });
  };

  if (anatomy.isPending) {
    return <Loading rows={8} />;
  }
  if (!anatomy.data) {
    const missing = anatomy.error instanceof HttpError && anatomy.error.status === 404;
    // ST-43: a record that does not exist and a read that failed are said apart.
    return (
      <>
        <PageHead title={runId} />
        <ErrorState {...(missing ? {} : { onRetry: () => void anatomy.refetch() })}>
          {t(missing ? 'ux.detail.notFound' : 'ux.detail.failed')}
        </ErrorState>
      </>
    );
  }
  const data = anatomy.data;
  const recorded = data.interpretation.recorded;
  const key = caseKey;
  const graded = evalOf(score.data?.business.D?.result);
  const decidedAt = score.data?.verdicts.find((verdict) => verdict.score.stepNo === step)?.decidedAt ?? null;
  const resource = data.context.resource ?? null;
  const device = data.context.usualVsNow.find((row) => row.dimension === 'device')?.now ?? null;
  const again =
    key && (PERSON_KEYS as readonly string[]).includes(key)
      ? flowPath(key as PersonKey, 'review')
      : key && cases.opens(key)
        ? agentPath(key, 'review')
        : null;
  const none = noDecisionKey(data);
  const classification = data.truth.classification;
  // Who sent the agent's requests, as the run records it (AS-1); a sender this code does not know is shown as recorded.
  const subject = agent.data ? subjectOfSender(agent.data.sender) : null;
  const sender = agent.data
    ? subject && subject !== 'person'
      ? t(`ux.detail.sender.${subject}`)
      : agent.data.sender
    : null;
  const recordings = agentCase.data?.recorded ?? null;
  return (
    <>
      <PageHead
        kicker={
          <>
            {classification ? (
              <Badge tone="line">{t(`ux.detail.truth.${classification}`, { defaultValue: classification })}</Badge>
            ) : null}
            {key ? <CodeChip value={key} /> : null}
            {graded ? <EvalBadge result={graded} /> : null}
            {agent.data ? (
              <Badge tone="line" icon="bot">
                {t('ux.detail.agent')} · {sender}
              </Badge>
            ) : null}
            {recordings && recordings.runs > 0 ? (
              <Badge tone="line">
                {t('ux.detail.recorded', {
                  runs: formatNumber(recordings.runs, i18n.language),
                  same: formatNumber(recordings.sameAsLatest, i18n.language),
                })}
              </Badge>
            ) : null}
          </>
        }
        title={runId}
        status={<VerdictBadge verdict={none === 'ux.detail.none.failed' ? 'NONE' : verdictOf(recorded.finalAction)} />}
        desc={key ? titleOf(key, score.data?.title, i18n.language) : undefined}
        actions={
          <>
            {agent.data && key ? (
              <ButtonLink to={agentPath(key, 'result', `?run=${encodeURIComponent(runId)}`)} variant="secondary" icon="bot">
                {t('ux.detail.agentResult')}
              </ButtonLink>
            ) : null}
            {again ? (
              <ButtonLink to={again} variant="secondary" icon="refresh-cw">
                {t('ux.detail.again')}
              </ButtonLink>
            ) : null}
          </>
        }
      />
      <SummaryBar
        label={t('ux.detail.strip')}
        items={[
          {
            label: t('ux.detail.strip.request'),
            value: resource?.requestPath ? (
              <code className={styles.code} title={resource.requestPath}>
                {resource.httpMethod ?? ''} {resource.requestPath}
              </code>
            ) : (
              data.operation
            ),
          },
          { label: t('ux.detail.strip.device'), value: device ?? '—' },
          {
            label: t('ux.detail.strip.scores'),
            value:
              recorded.riskScore !== null
                ? `${recorded.riskScore.toFixed(2)} · ${recorded.confidence?.toFixed(2) ?? '—'}`
                : '—',
          },
          {
            label: t('ux.detail.strip.time'),
            value: data.interpretation.timings?.totalAnalysisMs != null
              ? `${t('ux.time.seconds', { value: formatDuration(data.interpretation.timings.totalAnalysisMs, i18n.language) })}${
                  recorded.applied
                    ? ` · ${t(`ux.live.applied.${recorded.applied === 'NEXT_REQUEST' ? 'NEXT_REQUEST' : 'BEFORE_RESPONSE'}`)}`
                    : ''
                }`
              : '—',
          },
          { label: t('ux.detail.strip.at'), value: decidedAt ? `${formatUtc(decidedAt)} ${t('ux.runs.utc')}` : '—' },
        ]}
      />
      {steps > 1 ? (
        <nav className={styles.steps} aria-label={t('ux.detail.steps')}>
          {Array.from({ length: steps }, (_, index) => index + 1).map((number) => (
            <Link
              key={number}
              to={`?${new URLSearchParams({ ...Object.fromEntries(params), step: String(number) }).toString()}`}
              replace
              className={styles.step}
              aria-current={number === step ? 'page' : undefined}
            >
              {t('ux.pick.requestNo', { n: number })}
            </Link>
          ))}
          <span className={styles.stepsNote}>{t('ux.result.decidingStepValue', { n: step, total: steps })}</span>
        </nav>
      ) : null}
      <Tabs
        idBase="detail"
        label={t('ux.detail.tabs')}
        value={tab}
        onChange={(id) => set('tab', id)}
        items={TABS.map((id) => ({ id, label: t(`ux.detail.tab.${id}`) }))}
      />
      <TabPanel idBase="detail" id={tab}>
        {tab === 'summary' ? (
          <SummaryTab runId={runId} step={step} anatomy={data} score={score.data ?? null} />
        ) : tab === 'controls' ? (
          <ControlsTab runId={runId} step={step} anatomy={data} score={score.data ?? null} />
        ) : tab === 'evidence' ? (
          <EvidenceTab runId={runId} step={step} anatomy={data} score={score.data ?? null} />
        ) : tab === 'prompt' ? (
          <PromptTab runId={runId} step={step} anatomy={data} score={score.data ?? null} />
        ) : tab === 'response' ? (
          <ResponseTab runId={runId} step={step} anatomy={data} score={score.data ?? null} />
        ) : tab === 'integrity' ? (
          <IntegrityTab runId={runId} step={step} anatomy={data} score={score.data ?? null} />
        ) : (
          <LearningTab runId={runId} step={step} anatomy={data} score={score.data ?? null} />
        )}
      </TabPanel>
    </>
  );
}
