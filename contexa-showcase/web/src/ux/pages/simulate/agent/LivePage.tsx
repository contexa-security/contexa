import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, Navigate, useParams } from 'react-router-dom';
import { useAgentCase, useAgentConfirmationAnswer, useAgentRun, useAgentTry } from '../../../../api/agentCase';
import { REFERENCE_SNAPSHOT, useAgentSnapshot } from '../../../../api/agentSnapshots';
import { useLiveConfig } from '../../../../api/queries';
import { formatNumber } from '../../../format';
import { AGENT_MAIN, agentPath, useAgentCases } from '../../../simulate/agent';
import { AgentSteps, Instruction } from '../../../simulate/AgentParts';
import { useLiveRows, useRecordRows, type AgentRow } from '../../../simulate/agentRows';
import { DelegatorPanel } from '../../../simulate/DelegatorPanel';
import { FlowSteps } from '../../../simulate/FlowFrame';
import { Badge, Button, ButtonLink, CodeChip, Icon, Loading, Note, PageHead } from '../../../ui';
import live from '../../../simulate/Live.module.css';
import styles from '../../../simulate/Agent.module.css';

/** The run states in which the agent's work is stored and its record can be read (ST-28). */
const STORED = new Set(['CONFIRMING', 'COMPLETED']);
const LIMITS = new Set(['CAP_TOOL_CALLS', 'CAP_DECISIONS', 'CAP_INPUT_TOKENS']);

/**
 * Step 3 of the agent delegation flow (기획안 7.6): the agent's requests arrive one row each with the five controls'
 * answers; when control D asks the delegating person, the visitor answers beside the requests as that person
 * (ST-23~ST-28). Once the run is stored its record (tool, path, Contexa's decisions) replaces the live rows.
 */
export default function AgentLivePage() {
  const { caseKey } = useParams();
  const cases = useAgentCases();
  if (cases.pending) {
    return (
      <>
        <FlowSteps current="live" />
        <Loading rows={6} />
      </>
    );
  }
  if (!caseKey || !cases.opens(caseKey)) {
    return <Navigate replace to="/simulate/agent" />;
  }
  return <Live caseKey={caseKey} />;
}

function Live({ caseKey }: { readonly caseKey: string }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const tried = useAgentTry(caseKey);
  const agentCase = useAgentCase(caseKey);
  const config = useLiveConfig();
  const view = tried.live;
  const status = view?.status ?? null;
  const confirmation = view?.agentConfirmation ?? null;
  const storedId = view === null ? tried.runId : status !== null && STORED.has(status) ? view.runId : null;
  const record = useAgentRun(storedId, confirmation?.stage ?? null);
  const liveRows = useLiveRows(view);
  const recordRows = useRecordRows(record.data);
  const answer = useAgentConfirmationAnswer();
  const snapshot = useAgentSnapshot(caseKey === AGENT_MAIN ? REFERENCE_SNAPSHOT : null);
  const recorded = agentCase.data?.recorded?.runId ?? snapshot.data?.runId ?? null;
  const rows: readonly AgentRow[] = record.data ? recordRows : liveRows;
  const data = agentCase.data ?? null;
  const delegator = data ? t(`ux.person.${data.protagonist}`, { defaultValue: data.protagonist }) : '…';
  const done = record.data !== undefined && (view === null || status === 'COMPLETED');
  const runId = record.data?.runId ?? view?.runId ?? tried.runId;
  const marked =
    confirmation?.stepNo ??
    record.data?.confirmation?.stepNo ??
    rows.find((row) => row.cells.D === 'CONFIRM')?.stepNo ??
    null;

  const head = (pill: ReactNode = null) => (
    <PageHead
      kicker={
        <>
          <Badge tone="line" icon="bot">
            {t('ux.menu.agent')}
          </Badge>
          <CodeChip value={caseKey} />
          {runId ? <CodeChip value={runId} copy /> : null}
        </>
      }
      title={t('ux.agentLive.title')}
      status={pill}
    />
  );

  if (tried.pending) {
    return (
      <>
        <FlowSteps current="live" />
        <Loading rows={6} />
      </>
    );
  }
  if (view === null && tried.runId === null) {
    // ST-19: no run of this case yet, neither current nor stored.
    return (
      <>
        <FlowSteps current="live" />
        {head()}
        <Note>{t('ux.live.notSent')}</Note>
        <div className={live.footer}>
          <ButtonLink to={agentPath(caseKey, 'review')} variant="primary" iconAfter="arrow-right">
            {t('ux.live.toReview')}
          </ButtonLink>
        </div>
      </>
    );
  }
  if (status === 'FAILED' || status === 'EXPIRED') {
    // ST-16: the run ended without its work done; the visitor sends it again or reads a stored real run.
    return (
      <>
        <FlowSteps current="live" />
        {head()}
        <Note tone="warn">{t('ux.agentLive.failed')}</Note>
        <div className={live.footer}>
          <ButtonLink to={agentPath(caseKey, 'review')} variant="primary" icon="refresh-cw">
            {t('ux.live.retry')}
          </ButtonLink>
          {recorded ? (
            <ButtonLink to={`/runs/${encodeURIComponent(recorded)}`} variant="text">
              {t('ux.review.recorded')}
            </ButtonLink>
          ) : null}
        </div>
      </>
    );
  }

  const asked = status === 'CONFIRMING' && confirmation?.stage === 'ASKED';
  const pill = done ? (
    <Badge tone="none" icon="check">
      {t('ux.live.status.done')}
    </Badge>
  ) : asked ? (
    <Badge tone="stepup" icon="user-round-check">
      {t('ux.agentLive.status.asked')}
    </Badge>
  ) : status === 'COMPLETED' ? (
    <Badge tone="none" icon="hourglass">
      {t('ux.live.status.storing')}
    </Badge>
  ) : (
    <span className={live.livePill} role="status">
      <span className={live.liveDot} aria-hidden="true" />
      {t('ux.agentLive.status.working')}
    </span>
  );
  const limit = record.data && LIMITS.has(record.data.stopReason) ? record.data.stopReason : null;
  const n = (value: number) => formatNumber(value, i18n.language);

  return (
    <>
      <FlowSteps current="live" />
      {head(pill)}
      {status === 'QUEUED' && view ? (
        <Note icon="hourglass">
          {t('ux.live.queued', { position: view.queuePosition })}
          {view.queueWaitSeconds !== null ? ` ${t('ux.live.queuedWait', { seconds: view.queueWaitSeconds })}` : ''}
        </Note>
      ) : null}
      {status === 'STARTING' ? <Note icon="hourglass">{t('ux.agentLive.starting')}</Note> : null}
      <div className={styles.liveLayout}>
        <div className={styles.liveMain}>
          <section className={styles.panel} aria-labelledby="agent-steps-title">
            <header className={styles.panelHead}>
              <h2 id="agent-steps-title" className={styles.panelTitle}>
                {t('ux.agentLive.steps.title')}
              </h2>
              <p className={styles.panelSub}>{t('ux.agentLive.steps.sub')}</p>
            </header>
            {rows.length > 0 ? (
              <AgentSteps rows={rows} caption={t('ux.agentLive.steps.title')} marked={marked} />
            ) : (
              <p className={styles.working}>
                <Icon name="loader-circle" size="md" />
                {t('ux.agentLive.working')}
              </p>
            )}
          </section>
          <Summary rows={rows} />
        </div>
        <aside className={styles.liveSide}>
          {confirmation ? <DelegatorPanel confirmation={confirmation} delegator={delegator} answer={answer} /> : null}
          <section className={styles.panel} aria-labelledby="agent-work-title">
            <header className={styles.panelHead}>
              <h2 id="agent-work-title" className={styles.panelTitle}>
                {t('ux.agentLive.work.title')}
              </h2>
            </header>
            <div className={styles.panelBody}>
              {data ? <Instruction text={data.instruction[language] ?? data.instruction.en ?? ''} /> : null}
              <dl className={styles.workFacts}>
                <dt>{t('ux.agentLive.work.agent')}</dt>
                <dd>{data?.agentTitle[language] ?? '…'}</dd>
                {record.data ? (
                  <>
                    <dt>{t('ux.agentLive.work.model')}</dt>
                    <dd>{record.data.agentModel}</dd>
                    <dt>{t('ux.agentLive.work.sent')}</dt>
                    <dd>{t('ux.agentLive.work.sentValue', { n: n(record.data.steps.length), count: record.data.steps.length })}</dd>
                  </>
                ) : null}
              </dl>
              {limit ? <Note tone="warn">{t(`ux.agentLive.limit.${limit}`)}</Note> : null}
              {record.data?.finalAnswer ? (
                <details>
                  <summary>{t('ux.agentLive.work.answer')}</summary>
                  <p className={styles.answer} lang="en">
                    {record.data.finalAnswer}
                  </p>
                </details>
              ) : null}
            </div>
          </section>
        </aside>
      </div>

      <div className={live.footer}>
        {done && runId ? (
          <>
            <ButtonLink
              to={agentPath(caseKey, 'result', `?run=${encodeURIComponent(runId)}`)}
              variant="primary"
              size="lg"
              iconAfter="arrow-right"
            >
              {t('ux.live.toResult')}
            </ButtonLink>
            <ButtonLink to={`/runs/${encodeURIComponent(runId)}`} variant="text">
              {t('ux.live.raw')}
            </ButtonLink>
          </>
        ) : (
          <Button
            variant="primary"
            size="lg"
            iconAfter="arrow-right"
            disabledReason={t(asked ? 'ux.agentLive.wait.asked' : 'ux.agentLive.wait.working')}
          >
            {t('ux.live.toResult')}
          </Button>
        )}
        {view && !done && config.data ? <span className={live.footerNote}>{t('ux.agentLive.wait.hint')}</span> : null}
        <Link to="/simulate/agent" className={live.footerLink}>
          {t('ux.flow.changeScenario')}
        </Link>
      </div>
    </>
  );
}

/** The two summaries under the rows: what the four existing controls did, and what Contexa did. */
function Summary({ rows }: { readonly rows: readonly AgentRow[] }) {
  const { t } = useTranslation();
  if (rows.length === 0) {
    return null;
  }
  const existing = (['A', 'B', 'C1', 'C2'] as const).every((control) =>
    rows.every((row) => row.cells[control] === 'ALLOW'),
  );
  const stop = rows.find((row) => row.cells.D !== null && row.cells.D !== 'ALLOW' && row.cells.D !== 'PENDING');
  const deciding = rows.some((row) => row.cells.D === null || row.cells.D === 'PENDING');
  return (
    <div className={live.summary}>
      <section className={live.summaryCard} aria-labelledby="agent-summary-existing">
        <h3 id="agent-summary-existing" className={live.summaryLabel}>
          {t('ux.control.existing')}
        </h3>
        <p className={live.summaryValue}>
          {existing ? t('ux.agentLive.summary.allAllowed', { n: rows.length }) : t('ux.agentLive.summary.someStopped')}
        </p>
      </section>
      <section className={live.summaryCard} data-contexa="true" aria-labelledby="agent-summary-contexa">
        <h3 id="agent-summary-contexa" className={live.summaryLabel}>
          Contexa
        </h3>
        <p className={live.summaryValue}>
          {stop
            ? t(stop.cells.D === 'CONFIRM' ? 'ux.agentLive.summary.asked' : 'ux.agentLive.summary.stopped', {
                n: stop.stepNo,
              })
            : deciding
              ? t('ux.live.holding')
              : t('ux.agentLive.summary.passed', { n: rows.length })}
        </p>
      </section>
    </div>
  );
}
