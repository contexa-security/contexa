import { useEffect, useRef, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom';
import { useAnatomy, useBeforeSend, useReceived } from '../../../../api/anatomy';
import { useBenchmark } from '../../../../api/benchmark';
import { useLabOptions, type LabCase } from '../../../../api/lab';
import { useTeasers } from '../../../../api/teasers';
import type { LiveDecision, LiveLayer, LiveRunView } from '../../../../api/types';
import { CONTROL_ORDER, type ControlId } from '../../../../domain/verdict';
import { useTryAnalysis, useTryRun } from '../../../simulate/tryRun';
import { formatDuration, formatNumber } from '../../../format';
import { ControlLanes, type LaneRow } from '../../../simulate/ControlLanes';
import { DecisionProgress } from '../../../simulate/DecisionProgress';
import { FlowSteps } from '../../../simulate/FlowFrame';
import {
  EXISTING,
  contextChips,
  controlVerdict,
  flowPath,
  personCase,
  storedResend,
  type PersonCase,
} from '../../../simulate/person';
import { useRecordedRun } from '../../../simulate/RecordedFallback';
import { ChallengeCard, NoMailbox, ReleaseCard } from '../../../simulate/Recovery';
import { usePersonRuns } from '../../../simulate/useFlow';
import { useLiveActions } from '../../../simulate/useLiveActions';
import { Badge, Button, ButtonLink, CodeChip, Loading, Note, PageHead } from '../../../ui';
import styles from '../../../simulate/Live.module.css';

/** The run states during which the step still follows the run. */
const GOING = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED', 'CONFIRMING']);
const RELEASE_ENDED = new Set(['DONE', 'NO_MAILBOX', 'ABANDONED', 'EXPIRED', 'FAILED']);
const PRIOR_REFUSALS = new Set(['ACCOUNT_BLOCKED', 'MFA_CHALLENGE_REQUIRED']);

/**
 * Step 3 (기획안 7.0 d-live): the five security controls answer the same request at once, row by row as the answers
 * arrive, while Contexa's row holds the response and the panel beside it shows what the engine checks (F-5). The
 * extra check and the release of a block are lived here (ST-9~ST-15); every state of the run has its own words
 * (구현계획서 9절). Every value is the run's own record.
 */
export default function LivePage() {
  const { caseKey } = useParams();
  const scenario = personCase(caseKey);
  if (!scenario) {
    return <Navigate replace to="/simulate/person" />;
  }
  return <Live scenario={scenario} />;
}

function Live({ scenario }: { readonly scenario: PersonCase }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const key = scenario.key;
  const options = useLabOptions();
  const labCase = options.data?.cases.find((candidate) => candidate.key === key) ?? null;
  const steps = labCase?.steps ?? 1;
  const multi = steps > 1;
  const run = useTryRun(key, steps);
  const view: LiveRunView | null = run.view;
  const analysis = useTryAnalysis(view, run.stored, 1);
  const actions = useLiveActions();
  const runs = usePersonRuns();
  const recordedRun = useRecordedRun(key);
  const teasers = useTeasers();
  const benchmark = useBenchmark(null);
  const asked = useRef<string | null>(null);
  const triedRelease = useRef<string | null>(null);
  const attacker = scenario.role === 'attacker';

  // ST-9: the compromised account asks for the code at once; it goes to the account owner's mailbox.
  useEffect(() => {
    if (
      attacker &&
      view?.status === 'CHALLENGE' &&
      view.challenge?.stage === 'WAITING' &&
      asked.current !== view.liveRunId
    ) {
      asked.current = view.liveRunId;
      void actions.act('code');
    }
    // `actions` is recreated on every render; the run's state is what matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attacker, view?.status, view?.challenge?.stage, view?.liveRunId]);

  // ST-14: the compromised account asks for the release of a block at once; its code goes to the owner's mailbox too.
  useEffect(() => {
    if (
      attacker &&
      view?.status === 'BLOCKED' &&
      view.release?.stage === 'BLOCKED' &&
      triedRelease.current !== view.liveRunId
    ) {
      triedRelease.current = view.liveRunId;
      void actions.act('release-start');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attacker, view?.status, view?.release?.stage, view?.liveRunId]);

  const runId = view?.runId ?? null;
  const decision = analysis.decision;
  // A case of several requests: the panel follows the last request that has a decision of its own (a request refused
  // by an earlier decision has none).
  const panelStep = multi
    ? Math.max(
        1,
        ...(view?.steps ?? [])
          .filter((step) => step.layers.D && !PRIOR_REFUSALS.has(step.layers.D.ruleId ?? ''))
          .map((step) => step.stepNo),
      )
    : 1;
  const panel = useTryAnalysis(view, run.stored, panelStep);
  const layersOf = (stepNo: number) => view?.steps.find((step) => step.stepNo === stepNo)?.layers ?? {};
  const first = layersOf(1);
  const last = layersOf(steps);
  const contexa = first.D ?? null;
  const allAnswered =
    CONTROL_ORDER.every((control) => (multi ? last : first)[control] !== undefined) ||
    (multi && view?.status === 'COMPLETED');
  const challenge = view?.challenge ?? null;
  const release = view?.release ?? null;
  const checkOpen =
    !attacker && challenge !== null && !['DONE', 'NO_MAILBOX', 'ABANDONED'].includes(challenge.stage);
  const releaseOpen = scenario.role === 'owner' && release !== null && !RELEASE_ENDED.has(release.stage);
  const refusedEarlier = PRIOR_REFUSALS.has(contexa?.ruleId ?? '') && view?.status === 'COMPLETED';
  const done =
    allAnswered && (decision !== null || analysis.missing || refusedEarlier) && !checkOpen && !releaseOpen;
  const recorded = done && (run.stored || view?.status === 'COMPLETED');
  const received = useReceived(recorded ? runId : null, panelStep);
  const anatomy = useAnatomy(recorded ? runId : null, panelStep);
  const before = useBeforeSend(key, 1).data?.comparison ?? null;
  const comparison = received.data ?? before;
  const going = view !== null && GOING.has(view.status);
  const prediction = runs.prediction(key)?.call.engine ?? null;
  const resumed = teasers.data?.teasers.find((teaser) => teaser.key === 'CHALLENGE_OUTCOMES')?.values[
    'resumed'
  ];
  const benchmarkCase = benchmark.data?.cases.find((candidate) => candidate.key === key) ?? null;
  const measured = benchmarkCase ? { runs: benchmarkCase.runs, actions: benchmarkCase.engineActions } : null;

  const head = (status: ReactNode = null) => (
    <PageHead
      kicker={
        <>
          <Badge tone="line" icon={scenario.icon}>
            {t(`ux.review.kind.${key}`)}
          </Badge>
          <CodeChip value={key} />
          {runId ? <CodeChip value={runId} copy /> : null}
          {prediction ? (
            <span className={styles.expected}>
              {t('ux.live.expected', {
                call: t(`ux.review.predict.${prediction === 'ALLOW' ? 'ALLOW' : 'BLOCK'}.title`),
              })}
            </span>
          ) : null}
        </>
      }
      title={t('ux.live.title')}
      status={status}
    />
  );

  if (run.pending || options.isPending) {
    return (
      <>
        <FlowSteps current="live" />
        <Loading rows={6} />
      </>
    );
  }
  if (view === null) {
    // ST-19: no run of this scenario yet, neither current nor stored.
    return (
      <>
        <FlowSteps current="live" />
        {head()}
        <Note>{t('ux.live.notSent')}</Note>
        <div className={styles.footer}>
          <ButtonLink to={flowPath(key, 'review')} variant="primary" iconAfter="arrow-right">
            {t('ux.live.toReview')}
          </ButtonLink>
        </div>
      </>
    );
  }
  if (view.status === 'FAILED' || view.status === 'EXPIRED') {
    // ST-16: the run ended without a decision; the visitor sends it again or reads a stored real run.
    return (
      <>
        <FlowSteps current="live" />
        {head()}
        <Note tone="warn">{t('ux.live.failed')}</Note>
        <div className={styles.footer}>
          <ButtonLink to={flowPath(key, 'review')} variant="primary" icon="refresh-cw">
            {t('ux.live.retry')}
          </ButtonLink>
          {recordedRun ? (
            <ButtonLink to={`/runs/${recordedRun}`} variant="text">
              {t('ux.review.recorded')}
            </ButtonLink>
          ) : null}
        </div>
      </>
    );
  }

  const status = recorded ? (
    <Badge tone="none" icon="check">
      {t('ux.live.status.done')}
    </Badge>
  ) : done ? (
    <Badge tone="none" icon="hourglass">
      {t('ux.live.status.storing')}
    </Badge>
  ) : (
    <span className={styles.livePill} role="status">
      <span className={styles.liveDot} aria-hidden="true" />
      {analysis.wait
        ? t('ux.live.status.deciding', { seconds: formatDuration(analysis.wait.waitedMs, i18n.language) })
        : t('ux.live.status.decidingPlain')}
    </span>
  );

  return (
    <>
      <FlowSteps current="live" />
      {head(status)}
      {view.status === 'QUEUED' ? (
        <Note icon="hourglass">
          {t('ux.live.queued', { position: view.queuePosition })}
          {view.queueWaitSeconds !== null ? ' ' : null}
          {view.queueWaitSeconds !== null
            ? t('ux.live.queuedWait', { seconds: view.queueWaitSeconds })
            : null}
        </Note>
      ) : null}
      <div className={styles.layout}>
        <div className={styles.main}>
          {Array.from({ length: multi ? steps : 1 }, (_, index) => (
            <StepLanes
              key={index}
              stepNo={index + 1}
              view={view}
              stored={run.stored}
              labCase={labCase}
              multi={multi}
              decision={index === 0 ? decision : null}
            />
          ))}
          <Summary view={view} decision={decision} multi={multi} />
        </div>
        <aside className={styles.side}>
          <DecisionProgress
            stages={panel.stages ?? []}
            decision={panel.decision}
            wait={panel.wait}
            step={multi ? panelStep : null}
            anatomy={anatomy.data ?? null}
            context={comparison ? contextChips(t, comparison.businessFacts) : []}
            compared={comparison?.comparedCount ?? null}
            departed={comparison?.departureCount ?? null}
            httpStatus={view.steps.find((step) => step.stepNo === panelStep)?.layers.D?.httpStatus ?? null}
            measured={measured}
          />
          {comparison && !received.data ? (
            <p className={styles.sourceNote}>
              {t('ux.live.contextSource')} <CodeChip value={comparison.runId} />
            </p>
          ) : null}
        </aside>
      </div>

      {attacker && challenge?.stage === 'NO_MAILBOX' ? <NoMailbox kind="check" /> : null}
      {attacker && release?.stage === 'NO_MAILBOX' ? <NoMailbox kind="release" /> : null}
      {!attacker && challenge ? (
        <ChallengeCard
          challenge={challenge}
          act={actions.act}
          onRestart={() => navigate(flowPath(key, 'review'))}
          resumed={typeof resumed === 'number' ? resumed : null}
        />
      ) : null}
      {scenario.role === 'owner' && release ? (
        <ReleaseCard
          release={release}
          act={actions.act}
          defaultReason={releaseReason(t, labCase)}
          onRestart={() => navigate(flowPath(key, 'review'))}
        />
      ) : null}
      {actions.failed ? <Note tone="warn">{t('ux.live.actionFailed')}</Note> : null}

      <div className={styles.footer}>
        {recorded && runId ? (
          <>
            <ButtonLink
              to={flowPath(key, 'result', `?run=${encodeURIComponent(runId)}`)}
              variant="primary"
              size="lg"
              iconAfter="arrow-right"
            >
              {t('ux.live.toResult')}
            </ButtonLink>
            <ButtonLink to={`/runs/${encodeURIComponent(runId)}?tab=response`} variant="text">
              {t('ux.live.raw')}
            </ButtonLink>
          </>
        ) : (
          <Button
            variant="primary"
            size="lg"
            iconAfter="arrow-right"
            disabledReason={t(done ? 'ux.live.status.storing' : 'ux.live.wait.deciding')}
          >
            {t('ux.live.toResult')}
          </Button>
        )}
        {going && !done ? <span className={styles.footerNote}>{t('ux.live.wait.hint')}</span> : null}
        {!going && !recorded && done ? (
          <span className={styles.footerNote}>{t('ux.live.wait.storingHint')}</span>
        ) : null}
        <Link to="/simulate/person" className={styles.footerLink}>
          {t('ux.flow.changeScenario')}
        </Link>
      </div>
    </>
  );
}

/** The reason a real user files the release with: the case's approval if it records one, else plain words (ST-15). */
function releaseReason(t: ReturnType<typeof useTranslation>['t'], labCase: LabCase | null): string {
  const approval = labCase?.facts.find((fact) => fact.kind === 'APPROVAL') ?? null;
  if (!approval) {
    return t('ux.recovery.release.reasonPlain');
  }
  return t('ux.recovery.release.reasonApproval', {
    project: labCase?.requests[0]?.project ?? '-',
    approver: approval.approver ?? '-',
    max: approval.maxItems ?? '-',
  });
}

/** One request's five rows; a case of several requests names each request above its rows. */
function StepLanes({
  stepNo,
  view,
  stored,
  labCase,
  multi,
  decision,
}: {
  readonly stepNo: number;
  readonly view: LiveRunView;
  readonly stored: boolean;
  readonly labCase: LabCase | null;
  readonly multi: boolean;
  /** The step's decision when the parent already read it (the first step); the others read their own. */
  readonly decision: LiveDecision | null;
}) {
  const { t, i18n } = useTranslation();
  const own = useTryAnalysis(multi && stepNo > 1 ? view : null, stored, stepNo);
  // A run read from its stored records has no live check card; the request sent again after a passed check is the
  // step's own stored record (P-8, 5-2).
  const storedCheck = useAnatomy(stored ? view.runId : null, stepNo).data?.recovery?.challenge ?? null;
  const resend = storedResend(storedCheck);
  const stepDecision = stepNo === 1 ? decision : own.decision;
  const layers = view.steps.find((step) => step.stepNo === stepNo)?.layers ?? {};
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const request = labCase?.requests[stepNo - 1] ?? null;
  const fact = request?.document?.fact ?? null;
  const document = fact !== null ? (labCase?.facts[fact - 1]?.document ?? null) : null;
  const rows: LaneRow[] = CONTROL_ORDER.map((control) => {
    const layer: LiveLayer | undefined = layers[control];
    return {
      control,
      verdict: controlVerdict(control, layer ?? null, control === 'D' ? stepDecision : null),
      items: layer?.deliveredItems ?? null,
      ms: control === 'D' && layer?.outcome === 'HELD' && !stepDecision ? null : (layer?.elapsedMs ?? null),
      sub: t(`ux.review.controls.${control}`),
      ...(control === 'D' && !layer ? { pending: t('ux.live.deciding') } : {}),
    };
  });
  return (
    <section
      className={styles.lanesCard}
      aria-label={multi ? t('ux.live.stepLabel', { n: stepNo }) : t('ux.live.lanes')}
    >
      {multi ? (
        <p className={styles.stepHead}>
          <b>{t('ux.pick.requestNo', { n: stepNo })}</b>
          {document?.title?.[language] ? <span>{document.title[language]}</span> : null}
        </p>
      ) : null}
      <ControlLanes rows={rows} label={t('ux.live.lanes')} />
      {resend ? (
        <p className={styles.resent}>
          <Badge tone="allow" icon="check">
            {t('ux.recovery.retried', {
              count: resend.items,
              n: formatNumber(resend.items, i18n.language),
              status: resend.status,
            })}
          </Badge>
        </p>
      ) : null}
    </section>
  );
}

/** The two summaries under the rows: the four existing controls together, and Contexa (기획안 7.0 d-live 대비 요약). */
function Summary({
  view,
  decision,
  multi,
}: {
  readonly view: LiveRunView;
  readonly decision: LiveDecision | null;
  readonly multi: boolean;
}) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const handed = (control: ControlId) =>
    view.steps.reduce((sum, step) => sum + (step.layers[control]?.deliveredItems ?? 0), 0);
  const first = view.steps.find((step) => step.stepNo === 1)?.layers ?? {};
  const existing = EXISTING.map((control) => first[control] ?? null);
  const answered = existing.every((layer) => layer !== null);
  const slowest = answered ? Math.max(...existing.map((layer) => layer?.elapsedMs ?? 0)) : null;
  const allowed = existing.filter((layer) => layer?.outcome === 'DELIVERED').length;
  const contexa = first.D ?? null;
  const items = EXISTING.map((control) => handed(control));
  const same = items.every((value) => value === items[0]);
  return (
    <div className={styles.summary}>
      <section className={styles.summaryCard} aria-labelledby="summary-existing">
        <h3 id="summary-existing" className={styles.summaryLabel}>
          {t('ux.control.existing')}
        </h3>
        <p className={styles.summaryValue}>
          {slowest !== null
            ? allowed === 4
              ? t('ux.live.allAllowed', { seconds: formatDuration(slowest, i18n.language) })
              : t('ux.live.someAllowed', { allowed, stopped: 4 - allowed })
            : '…'}
        </p>
        <p className={styles.summaryDetail}>
          {answered
            ? same
              ? t('ux.live.exportedTimesFour', { n: n(items[0] ?? 0) })
              : t('ux.live.exportedSum', { n: n(items.reduce((sum, value) => sum + value, 0)) })
            : null}
        </p>
      </section>
      <section className={styles.summaryCard} data-contexa="true" aria-labelledby="summary-contexa">
        <h3 id="summary-contexa" className={styles.summaryLabel}>
          Contexa
        </h3>
        <p className={styles.summaryValue}>
          {contexa
            ? t('ux.facts.items', {
                count: multi ? handed('D') : contexa.deliveredItems,
                n: n(multi ? handed('D') : contexa.deliveredItems),
              })
            : t('ux.live.held')}
        </p>
        <p className={styles.summaryDetail}>
          {decision ? t(`ux.live.appliedLong.${decision.applied}`) : t('ux.live.holding')}
        </p>
      </section>
    </div>
  );
}
