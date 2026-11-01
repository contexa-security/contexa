import { useTranslation } from 'react-i18next';
import { Navigate, useParams, useSearchParams } from 'react-router-dom';
import {
  useAgentCase,
  useAgentRun,
  type AgentDelegation,
  type AgentResent,
  type AgentRunView,
} from '../../../../api/agentCase';
import { useAgentSnapshot } from '../../../../api/agentSnapshots';
import { useAnatomy } from '../../../../api/anatomy';
import { useJourney } from '../../../../api/journey';
import { CONTROL_ORDER } from '../../../../domain/verdict';
import { formatNumber, formatUtc } from '../../../format';
import {
  AGENT_MAIN,
  CONFIRMATION_RULE,
  actualCall,
  agentConclusion,
  agentPath,
  firstStop,
  plusMinutes,
  recordedWords,
  rememberedCall,
  senderWords,
  useAgentCases,
} from '../../../simulate/agent';
import { AgentCellBadge, AgentSteps } from '../../../simulate/AgentParts';
import { useRecordRows } from '../../../simulate/agentRows';
import { CONTROL_TONE } from '../../../simulate/controls';
import { Evidence } from '../../../simulate/Evidence';
import { FlowProgress, FlowSteps } from '../../../simulate/FlowFrame';
import { companyClock } from '../../../simulate/person';
import { useAgentRuns, useGroupRuns } from '../../../simulate/useFlow';
import { Badge, ButtonLink, CodeChip, EvalBadge, Icon, Loading, Note, PageHead } from '../../../ui';
import { breakable } from '../../../ui/breakable';
import result from '../../../simulate/Result.module.css';
import styles from '../../../simulate/Agent.module.css';
import sim from '../../../simulate/Simulate.module.css';

/** The stored real run of the main case in which the delegating person reported the agent (DEC-26). */
const REPORT_SNAPSHOT = 'T5-confirm-report';
const AGENT_EXPERIENCE = 'E4';

/**
 * Step 4 of the agent delegation flow (기획안 7.6, F-6): the conclusion in one sentence, each control's answer across
 * the agent's work, the requests one row each, the delegating person's confirmation (and, for the main case, the
 * stored run in which the person reported the agent instead), the evidence and the next checks. Every number is the
 * portal's scoring of the run (/api/runs/{id}/agent); the screen never judges the run itself.
 */
export default function AgentResultPage() {
  const { caseKey } = useParams();
  const cases = useAgentCases();
  if (cases.pending) {
    return (
      <>
        <FlowSteps current="result" />
        <Loading rows={6} />
      </>
    );
  }
  if (!caseKey || !cases.opens(caseKey)) {
    return <Navigate replace to="/simulate/agent" />;
  }
  return <Result caseKey={caseKey} />;
}

function Result({ caseKey }: { readonly caseKey: string }) {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const own = useGroupRuns([caseKey]);
  const asked = params.get('run');
  const runId = asked ?? own.latest(caseKey)?.runId ?? null;
  const record = useAgentRun(runId);
  if (!asked && !own.ready) {
    return (
      <>
        <FlowSteps current="result" />
        <Loading rows={6} />
      </>
    );
  }
  if (runId === null) {
    return (
      <>
        <FlowSteps current="result" />
        {/* A visitor without a run of the scenario still lands on a titled screen (기획안 11절 6-7). */}
        <PageHead title={t('ux.agentResult.title')} />
        <Note>{t('ux.result.none')}</Note>
        <ButtonLink to={agentPath(caseKey, 'review')} variant="primary" iconAfter="arrow-right">
          {t('ux.live.toReview')}
        </ButtonLink>
      </>
    );
  }
  return (
    <>
      <FlowSteps current="result" />
      {record.isPending ? (
        <Loading rows={6} />
      ) : record.data ? (
        <RunResult caseKey={caseKey} run={record.data} />
      ) : (
        <Note tone="warn">{t('ux.result.unavailable')}</Note>
      )}
      <FlowProgress group="agent" />
    </>
  );
}

function RunResult({ caseKey, run }: { readonly caseKey: string; readonly run: AgentRunView }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const runs = useAgentRuns();
  const rows = useRecordRows(run);
  const agentCase = useAgentCase(caseKey).data ?? null;
  const journey = useJourney();
  // Whose run the screen shows (옛 MeasureNote): one of the visitor's own runs, or a stored run the address names.
  const ownRun = journey.data ? journey.data.runs.some((line) => line.runId === run.runId) : null;
  const stop = firstStop(run);
  const conclusion = agentConclusion(run);
  const decided = [...run.steps].reverse().find((step) => step.decision?.final_action) ?? null;
  const evidenceStep = stop?.decision?.final_action ? stop : decided;
  const anatomy = useAnatomy(evidenceStep ? run.runId : null, evidenceStep?.stepNo ?? 1);
  const recorded = anatomy.data?.interpretation?.recorded ?? null;
  const sent = run.proof?.sent ?? run.steps.length;
  const contexaCell = stop ? (rows.find((row) => row.stepNo === stop.stepNo)?.cells.D ?? null) : 'ALLOW';
  const tone =
    conclusion === 'passed'
      ? 'allow'
      : conclusion === 'stopped' || conclusion === 'confirmRejected'
        ? 'block'
        : conclusion === 'unfinished'
          ? 'none'
          : 'stepup';
  const icon =
    conclusion === 'passed' ? 'check' : conclusion === 'stopped' ? 'ban' : conclusion === 'unfinished' ? 'minus' : 'user-round-check';
  const existingStops = (['A', 'B', 'C1', 'C2'] as const).filter(
    (control) => run.proof?.controls[control]?.firstStopStep != null,
  ).length;
  const scored = caseKey === AGENT_MAIN;
  const serverCall = scored
    ? (runs.predictions.find((prediction) => prediction.experience === AGENT_EXPERIENCE) ?? null)
    : null;
  const myCall = scored ? (serverCall?.call.engine ?? null) : rememberedCall(caseKey);
  const actual = actualCall(run);
  const confirmationStep =
    run.confirmation?.stepNo ?? run.steps.find((step) => step.outcomes.D?.rule === CONFIRMATION_RULE)?.stepNo ?? null;

  return (
    <>
      <section className={result.verdict} aria-labelledby="result-title" data-tone={tone}>
        <span className={result.verdictIcon} data-tone={tone}>
          <Icon name={icon} size="xxl" />
        </span>
        <div className={result.verdictMain}>
          <h1 id="result-title" tabIndex={-1} className={result.verdictTitle}>
            {t(`ux.agentResult.conclusion.${conclusion}`, { n: stop?.stepNo ?? sent, sent: n(sent), count: sent })}
          </h1>
          <p className={result.verdictSub}>
            {existingStops === 0
              ? t('ux.agentResult.existing.allPassed')
              : t('ux.agentResult.existing.mixed', { stopped: existingStops, passed: 4 - existingStops })}
          </p>
        </div>
        <dl className={result.verdictSide}>
          <dt>{t('ux.result.decidingStep')}</dt>
          <dd>{stop ? t('ux.result.decidingStepValue', { n: stop.stepNo, total: sent }) : t('ux.agentResult.noStop')}</dd>
          <dt>{t('ux.result.decision')}</dt>
          <dd>
            <AgentCellBadge cell={contexaCell} />
          </dd>
          {myCall ? (
            <>
              <dt>{t('ux.review.predict.title')}</dt>
              <dd>
                {scored && serverCall?.engineSameStop === true ? <EvalBadge result="correct" /> : null}
                {scored && serverCall?.engineSameStop === false ? (
                  <Badge tone="none">{t('ux.result.predictionDiffers')}</Badge>
                ) : null}{' '}
                {t(`ux.agentReview.predict.${myCall}.title`)}
                {!scored ? ` · ${t('ux.agentResult.actual', { call: t(`ux.agentReview.predict.${actual}.title`) })}` : null}
              </dd>
            </>
          ) : null}
          <dt>{t('ux.result.runId')}</dt>
          <dd className={styles.runLine}>
            <CodeChip value={run.runId} copy />
            {ownRun === null ? null : (
              <Badge tone="line">{t(ownRun ? 'ux.agentResult.source.own' : 'ux.agentResult.source.stored')}</Badge>
            )}
          </dd>
          {agentCase ? (
            <>
              <dt>{t('ux.agent.sender.label')}</dt>
              <dd>{senderWords(t, agentCase.sender)}</dd>
              <dt>{t('ux.agent.recorded.label')}</dt>
              <dd>{recordedWords(t, agentCase.recorded, i18n.language) ?? '—'}</dd>
            </>
          ) : null}
        </dl>
      </section>

      <div className={result.grid}>
        <div className={result.column}>
          <Controls run={run} />
        </div>
        <div className={result.column}>
          {confirmationStep !== null ? (
            <Confirmation
              run={run}
              caseKey={caseKey}
              stepNo={confirmationStep}
              delegation={run.delegation ?? agentCase?.delegation ?? null}
            />
          ) : null}
          {evidenceStep ? (
            <Evidence
              runId={run.runId}
              stepNo={evidenceStep.stepNo}
              risk={recorded?.riskScore ?? null}
              confidence={recorded?.confidence ?? null}
              reasoning={recorded?.reasoning ?? null}
              reasoningCode={recorded?.reasoningCode ?? null}
            />
          ) : (
            <Note>{t('ux.agentResult.noModel')}</Note>
          )}
        </div>
      </div>

      <section className={[styles.panel, styles.wide].join(' ')} aria-labelledby="agent-requests-title">
        <header className={styles.panelHead}>
          <h2 id="agent-requests-title" className={styles.panelTitle}>
            {t('ux.agentLive.steps.title')}
          </h2>
          <p className={styles.panelSub}>{t('ux.agentResult.steps.sub', { n: n(sent), count: sent })}</p>
        </header>
        <AgentSteps rows={rows} caption={t('ux.agentLive.steps.title')} marked={confirmationStep} />
      </section>

      <NextChecks caseKey={caseKey} runId={run.runId} />
    </>
  );
}

/** What each control let go across the agent's work, and the first request it did not answer with the data. */
function Controls({ run }: { readonly run: AgentRunView }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const proof = run.proof ?? null;
  return (
    <section className={result.card} aria-labelledby="agent-controls-title">
      <header className={result.cardHead}>
        <h2 id="agent-controls-title" className={result.cardTitle}>
          {t('ux.agentResult.controls.title')}
        </h2>
        <p className={result.cardSub}>
          {proof?.workNeeds != null
            ? t('ux.agentResult.controls.needs', { n: n(proof.workNeeds), count: proof.workNeeds })
            : t('ux.agentResult.controls.sub')}
        </p>
      </header>
      {proof ? (
        <div className={styles.countsScroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
          <table className={styles.counts}>
            <caption className="ux-sr-only">{t('ux.agentResult.controls.title')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.lanes.control')}</th>
                <th scope="col">{t('ux.agentResult.controls.firstStop')}</th>
                <th scope="col">{t('ux.agentResult.controls.left')}</th>
                <th scope="col">{t('ux.agentResult.controls.beyond')}</th>
              </tr>
            </thead>
            <tbody>
              {CONTROL_ORDER.map((control) => {
                const counts = proof.controls[control];
                const left = counts ? counts.documents + counts.items + counts.records + counts.changes : null;
                return (
                  <tr key={control} data-contexa={control === 'D' || undefined}>
                    <th scope="row">
                      <span className={result.exportName}>
                        <span className={sim.swatch} data-tone={CONTROL_TONE[control]} aria-hidden="true" />
                        {t(`ux.control.${control}`)}
                      </span>
                    </th>
                    <td>
                      {counts?.firstStopStep != null
                        ? t('ux.pick.requestNo', { n: counts.firstStopStep })
                        : t('ux.agentResult.controls.never')}
                    </td>
                    <td>{left === null ? '—' : n(left)}</td>
                    <td>{counts ? n(counts.beyondNeed) : '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <Note>{t('ux.agentResult.controls.unscored')}</Note>
      )}
      {proof ? (
        <details className={[styles.more, styles.moreCard].join(' ')}>
          <summary>{t('ux.agent.more')}</summary>
          <div className={styles.countsScroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
            <table className={styles.counts}>
              <caption className="ux-sr-only">{t('ux.agentResult.controls.kinds')}</caption>
              <thead>
                <tr>
                  <th scope="col">{t('ux.lanes.control')}</th>
                  {KINDS.map((kind) => (
                    <th key={kind} scope="col">
                      {t(`ux.agentResult.controls.${kind}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {CONTROL_ORDER.map((control) => {
                  const counts = proof.controls[control];
                  return (
                    <tr key={control} data-contexa={control === 'D' || undefined}>
                      <th scope="row">{t(`ux.control.${control}`)}</th>
                      {KINDS.map((kind) => (
                        <td key={kind}>{counts ? n(counts[kind]) : '—'}</td>
                      ))}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </details>
      ) : null}
    </section>
  );
}

/** What left at a control, by kind, as the portal scored the work (the table's "data let go" is their sum). */
const KINDS = ['documents', 'items', 'records', 'changes'] as const;

function resentWords(t: ReturnType<typeof useTranslation>['t'], key: string, resent: AgentResent | null): string | null {
  if (resent === null || resent.httpStatus === null) {
    return null;
  }
  // A request sent again with the same confirmation, or another one, says what it handed over when it was served.
  const served = resent.httpStatus >= 200 && resent.httpStatus < 300;
  return t(served && key !== 'ux.agentResult.confirm.resend' ? `${key}Served` : key, {
    status: resent.httpStatus,
    n: resent.deliveredItems,
    count: resent.deliveredItems,
  }) + (resent.ruleId ? ` · ${resent.ruleId}` : '');
}

/** The confirmation's status after the answer, in words; its code for a status not named here, a dash without one. */
function statusWords(t: ReturnType<typeof useTranslation>['t'], status: string | null | undefined): string {
  return status ? t(`ux.agentResult.confirm.status.${status}`, { defaultValue: status }) : '—';
}

/** The delegating person's confirmation as stored, and for the main case the stored run in which they reported it. */
function Confirmation({
  run,
  caseKey,
  stepNo,
  delegation,
}: {
  readonly run: AgentRunView;
  readonly caseKey: string;
  /** The request control D asked the delegating person about. */
  readonly stepNo: number;
  /** The delegation the run executed: its period counts from the run's company time. */
  readonly delegation: AgentDelegation | null;
}) {
  const { t } = useTranslation();
  const report = useAgentSnapshot(caseKey === AGENT_MAIN ? REPORT_SNAPSHOT : null).data ?? null;
  const confirmation = run.confirmation;
  const reported = report?.run.confirmation ?? null;
  const asked = run.steps.find((step) => step.stepNo === stepNo) ?? null;
  const ended = plusMinutes(run.companyTime, delegation?.validUntilMinutes);
  const yours = t('ux.agentResult.confirm.yours');
  const theirs = t('ux.agentResult.confirm.reported');
  const lines = (stored: AgentRunView['confirmation']) =>
    [
      resentWords(t, 'ux.agentResult.confirm.resend', stored?.resend ?? null),
      resentWords(t, 'ux.agentResult.confirm.reuse', stored?.reuse ?? null),
      resentWords(t, 'ux.agentResult.confirm.other', stored?.other ?? null),
    ].filter((line): line is string => line !== null);
  return (
    <section className={result.card} aria-labelledby="agent-confirm-title">
      <header className={result.cardHead}>
        <h2 id="agent-confirm-title" className={result.cardTitle}>
          {t('ux.agentResult.confirm.title')}
        </h2>
        <p className={result.cardSub}>
          {confirmation?.trigger
            ? t(`ux.agent.trigger.${confirmation.trigger}`, { defaultValue: confirmation.trigger })
            : t('ux.agentResult.confirm.sub')}
        </p>
      </header>
      <div className={styles.panelBody}>
        {confirmation?.decision === 'APPROVE' ? (
          <h3 className={styles.confirmTitle}>{t('ux.agentResult.confirm.approvedTitle')}</h3>
        ) : null}
        <dl className={styles.calls}>
          <div className={styles.call}>
            <dt>{yours}</dt>
            <dd>
              {confirmation?.decision
                ? t(`ux.agent.delegator.decided.${confirmation.decision}`)
                : t('ux.agentResult.confirm.unanswered')}
            </dd>
            {confirmation?.decision ? null : (
              <dd className={styles.counterNote}>
                {t('ux.agentResult.confirm.whyLine', {
                  why: confirmation?.reason
                    ? t(`ux.agentResult.confirm.why.${confirmation.reason}`, { defaultValue: confirmation.reason })
                    : '—',
                })}
              </dd>
            )}
            {lines(confirmation).map((line) => (
              <dd key={line} className={styles.counterNote}>
                {line}
              </dd>
            ))}
          </div>
          {reported ? (
            <div className={styles.call}>
              <dt>{t('ux.agentResult.confirm.reported')}</dt>
              <dd>{t('ux.agentResult.confirm.reportedValue')}</dd>
              {lines(reported).map((line) => (
                <dd key={line} className={styles.counterNote}>
                  {line}
                </dd>
              ))}
              <dd className={styles.counterNote}>
                <CodeChip value={report?.runId ?? ''} />
              </dd>
            </div>
          ) : null}
        </dl>
        <details className={styles.more}>
          <summary>{t('ux.agent.more')}</summary>
          <dl className={styles.moreFacts}>
            <dt>{t('ux.agentResult.confirm.requestAt', { n: stepNo })}</dt>
            <dd>{companyClock(t, asked?.companyTime)}</dd>
            <dt>{t('ux.agentResult.confirm.delegationEnd')}</dt>
            <dd>{companyClock(t, ended)}</dd>
            <dt>
              {t('ux.agentResult.confirm.after')} · {yours}
            </dt>
            <dd>{statusWords(t, confirmation?.after?.status)}</dd>
            <dt>
              {t('ux.agentResult.confirm.authorization')} · {yours}
            </dt>
            <dd>{confirmation?.after?.authorizationId ? <code>{breakable(confirmation.after.authorizationId)}</code> : '—'}</dd>
            {reported && report ? (
              <>
                <dt>
                  {t('ux.agentResult.confirm.after')} · {theirs}
                </dt>
                <dd>{statusWords(t, reported.after?.status)}</dd>
                <dt>
                  {t('ux.agentResult.confirm.capturedAt')} · {theirs}
                </dt>
                <dd>{`${formatUtc(report.capturedAt)} ${t('ux.runs.utc')}`}</dd>
              </>
            ) : null}
          </dl>
        </details>
      </div>
    </section>
  );
}

/** The next checks: the control run of the main case (or the main case), the decision details, the request surge. */
function NextChecks({ caseKey, runId }: { readonly caseKey: string; readonly runId: string }) {
  const { t } = useTranslation();
  const first =
    caseKey === AGENT_MAIN
      ? { title: t('ux.agentResult.next.pair.title'), desc: t('ux.agentResult.next.pair.desc'), to: agentPath('N1', 'review'), action: t('ux.result.next.run', { key: 'N1' }) }
      : { title: t('ux.agentResult.next.other.title'), desc: t('ux.agentResult.next.other.desc'), to: '/simulate/agent', action: t('ux.agentResult.next.other.action') };
  return (
    <section aria-labelledby="next-title" className={result.next}>
      <div className={result.nextHead}>
        <h2 id="next-title" className={result.cardTitle}>
          {t('ux.result.next.title')}
        </h2>
        <p className={result.cardSub}>{t('ux.agentResult.next.sub')}</p>
      </div>
      <div className={result.nextCards}>
        <article className={result.nextCard} data-primary="true">
          <h3 className={result.nextTitle}>{first.title}</h3>
          <p className={result.nextDesc}>{first.desc}</p>
          <ButtonLink to={first.to} variant="primary" iconAfter="arrow-right">
            {first.action}
          </ButtonLink>
        </article>
        <article className={result.nextCard}>
          <h3 className={result.nextTitle}>{t('ux.result.next.detail.title')}</h3>
          <p className={result.nextDesc}>{t('ux.result.next.detail.desc')}</p>
          <ButtonLink to={`/runs/${encodeURIComponent(runId)}`}>{t('ux.result.next.detail.action')}</ButtonLink>
        </article>
        <article className={result.nextCard}>
          <h3 className={result.nextTitle}>{t('ux.agentResult.next.surge.title')}</h3>
          <p className={result.nextDesc}>{t('ux.agentResult.next.surge.desc')}</p>
          <ButtonLink to="/simulate/surge">{t('ux.agentResult.next.surge.action')}</ButtonLink>
        </article>
      </div>
    </section>
  );
}
