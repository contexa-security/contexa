import { useQueryClient } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useAnatomy } from '../../api/anatomy';
import { postJson } from '../../api/http';
import {
  analysisSettled,
  useBaseline,
  useEndedRun,
  useLiveAnalysis,
  useLiveRun,
  useRunScore,
} from '../../api/queries';
import type { LiveRunView } from '../../api/types';
import { AssessPanel } from '../../components/assessment/AssessPanel';
import { LiveChallenge } from '../../components/LiveChallenge';
import consoleStyles from '../../components/show/RoleConsole.module.css';
import { ReleasePanel } from '../../components/show/ReleasePanel';
import { StateScreen } from '../../components/StateScreen';
import { AnalysisPanel } from '../../components/show/AnalysisPanel';
import { ApproachStrip } from '../../components/show/ApproachStrip';
import { BaselinePanel } from '../../components/show/BaselinePanel';
import { LeakCounters } from '../../components/show/LeakCounters';
import { RoleConsole, type ConsoleRow } from '../../components/show/RoleConsole';
import { SceneConclusion, type ConclusionLine } from '../../components/show/SceneConclusion';
import { refusalOf, type GateRefusal } from '../../domain/live';
import {
  conclusion,
  decision,
  lanes,
  leakedThroughExisting,
  retryAnswer,
  SCENARIO,
  secondsText,
  type Conclusion,
  type EngineDecision,
  type LaneState,
  type Role,
  type SceneRequest,
} from '../../domain/show';
import type { ControlId } from '../../domain/verdict';
import { CONTROL_ORDER } from '../../domain/verdict';
import { useTurnstile } from '../../hooks/useTurnstile';
import styles from './StreamScene.module.css';

const ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED']);
const HOLDING = new Set(['BLOCK', 'CHALLENGE', 'ESCALATE']);
/** How long the analysis is still read after the run ended without a decision in it. */
const ANALYSIS_GRACE_MS = 20_000;
/** How long the analysis is still looked for after Contexa refused the request with a decision already in force. */
const NO_ANALYSIS_GRACE_MS = 5_000;

/** The visitor's gate to a new live run: the visitor cookie, the human check's key, and the runs left today. */
export interface LiveGateState {
  readonly visitorReady: boolean;
  readonly turnstileSiteKey: string | null;
  readonly remainingToday: number | null;
}

interface Attempt {
  readonly sending: boolean;
  readonly liveRunId: string | null;
  readonly refusal: GateRefusal | null;
}

interface StreamSceneProps {
  readonly role: Role;
  readonly gate: LiveGateState;
  /** The scene's first request as its case defines it (H-03). */
  readonly request: SceneRequest;
  /** The first act's request, so the second says what differs from it; null in the first act. */
  readonly previous: SceneRequest | null;
  /** The assessment reasons the portal offers, for the act's closing assessment. */
  readonly assessmentReasons: readonly string[];
  readonly onNext: () => void;
}

/** The visitor's call before sending (5A.3): shown next to what happened, not stored (the question is the act's own). */
type Prediction = 'YES' | 'NO' | 'UNSURE';

/**
 * Scenes 2 and 3 of docs/showcase/화면설계서.md. The visitor sends the export as the attacker or as the real owner and
 * the five approaches answer as the streams are read; Contexa's analysis stages arrive from the engine as it works.
 * The attacker can try again, and the second request really goes out from the same account. Every number on this
 * screen comes from this run; when Contexa did not stop the attack the screen says so.
 */
export function StreamScene({ role, gate, request, previous, assessmentReasons, onNext }: StreamSceneProps) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const baseline = useBaseline(request.employee);
  const live = useLiveRun(true);
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const [prediction, setPrediction] = useState<Prediction | null>(null);
  const [analysisGaveUp, setAnalysisGaveUp] = useState(false);
  const [noNewAnalysis, setNoNewAnalysis] = useState(false);
  const {
    container: turnstileContainer,
    token: turnstileToken,
    required: turnstileRequired,
    reset: resetTurnstile,
  } = useTurnstile(gate.turnstileSiteKey);
  const ready = gate.visitorReady && !(turnstileRequired && !turnstileToken) && prediction !== null;

  const current = live.data ?? null;
  const ended = useEndedRun(attempt?.liveRunId ?? null).data ?? null;
  const view: LiveRunView | null =
    attempt?.liveRunId == null
      ? null
      : (ended ?? (current?.liveRunId === attempt.liveRunId ? current : null));
  const viewActive = view !== null && ACTIVE.has(view.status);
  // A run of the scene before (the attacker waiting for a second try) is finished before this one starts.
  const otherActive =
    current !== null && ACTIVE.has(current.status) && current.liveRunId !== attempt?.liveRunId;

  const first = lanes(view, 1);
  const second = lanes(view, 2);
  // How many items the export announced (the server's stream count, #20); the case's own count until it does.
  const announced = CONTROL_ORDER.map(
    (control) => view?.steps.find((step) => step.stepNo === 1)?.streams?.[control],
  )
    .map((stream) => stream?.total ?? null)
    .find((value) => value !== null);
  const total = announced ?? request.items ?? 0;
  const firstDone = CONTROL_ORDER.every((control) => first[control].kind === 'done');

  const analysisRunning = view !== null && view.status !== 'QUEUED' && view.status !== 'STARTING';
  const analysis = useLiveAnalysis(
    attempt?.liveRunId ?? null,
    1,
    analysisRunning && !analysisGaveUp && !noNewAnalysis,
  );
  const stages = analysis.data?.stages ?? [];
  const engine = decision(stages);
  const settled = analysisSettled(analysis.data);
  const viewEnded = view !== null && !viewActive;
  useEffect(() => {
    if (!viewEnded || settled) {
      return undefined;
    }
    const timer = window.setTimeout(() => setAnalysisGaveUp(true), ANALYSIS_GRACE_MS);
    return () => window.clearTimeout(timer);
  }, [viewEnded, settled]);
  // An analysis runs only while no decision holds: a request Contexa refused with a decision already in force is not
  // analysed again, and after a short grace the panel says so instead of waiting.
  const refusedAtOnce =
    first.D.kind === 'done' &&
    first.D.outcome !== 'DELIVERED' &&
    first.D.outcome !== 'CUT' &&
    first.D.outcome !== 'UNRESOLVED';
  useEffect(() => {
    if (!refusedAtOnce || stages.length > 0) {
      return undefined;
    }
    const timer = window.setTimeout(() => setNoNewAnalysis(true), NO_ANALYSIS_GRACE_MS);
    return () => window.clearTimeout(timer);
  }, [refusedAtOnce, stages.length]);

  const ending = conclusion(role, first.D, engine, total);
  const retry = role === 'attacker' ? retryAnswer(second.D) : null;
  const awaitingRetry = view?.status === 'AWAITING' && view.awaitingStep === 2;
  const secondSent = view?.steps.some((step) => step.stepNo === 2) ?? false;
  // The second request goes out on the press and is answered when all five lanes are; the run tidies up after that.
  const retrying =
    role === 'attacker' &&
    view?.status === 'RUNNING' &&
    secondSent &&
    !CONTROL_ORDER.every((control) => second[control].kind === 'done');
  // The second try is named by the case's own request: its project and the type of the one document it asks for.
  const followUpText = {
    project: request.followUp?.project ?? '-',
    document: request.followUp?.documentType ? t(`show.documentType.${request.followUp.documentType}`) : '-',
  };

  async function send() {
    setAttempt({ sending: true, liveRunId: null, refusal: null });
    setAnalysisGaveUp(false);
    setNoNewAnalysis(false);
    const response = await postJson<LiveRunView & { reason?: string }>('/api/live/runs', {
      scenario: SCENARIO[role],
      turnstileToken,
    });
    resetTurnstile();
    const body = response.body;
    if (response.status === 202 && body && body.scenario !== SCENARIO[role]) {
      // The portal handed back the run of the scene before, still finishing; this scene waits for it to end.
      queryClient.setQueryData(['live-run'], body);
      setAttempt(null);
    } else if (response.status === 202 && body) {
      queryClient.setQueryData(['live-run'], body);
      setAttempt({ sending: false, liveRunId: body.liveRunId, refusal: null });
    } else {
      setAttempt({
        sending: false,
        liveRunId: null,
        refusal: refusalOf(response.status, body?.reason ?? null),
      });
    }
  }

  async function act(path: string, body: unknown = {}) {
    const response = await postJson<LiveRunView>(path, body);
    if (response.body && response.status < 300) {
      queryClient.setQueryData(['live-run'], response.body);
    }
  }

  const approval = request.approval;
  // The approval as the company records hold it: its purpose and status come from the case's record, never a phrase.
  const approvalFacts = {
    project: approval?.project ?? request.project ?? '-',
    purpose: approval?.purpose ? t(`show.purpose.${approval.purpose}`) : '-',
    status: approval?.status ? t(`show.factStatus.${approval.status}`) : '-',
  };
  const approvalText = approval
    ? t('show.console.approvalValue', {
        ...approvalFacts,
        approver: approval.approver ?? '-',
        max: approval.maxItems === null ? '-' : approval.maxItems.toLocaleString(i18n.language),
      })
    : t('show.console.approvalNone');
  const changes = previous ? differences(previous, request) : [];
  const rows: ConsoleRow[] = [
    {
      key: 'account',
      label: t('show.console.account'),
      value: t('show.console.accountValue', {
        name: request.employeeName,
        role: t(`lab.role.${request.role}`),
      }),
    },
    {
      key: 'time',
      label: t('show.console.time'),
      value: t(`lab.slot.${request.slot}`, { time: request.time }),
      changed: changes.includes('time'),
    },
    {
      key: 'network',
      label: t('show.console.network'),
      value:
        request.place === 'OFFICE'
          ? t('show.console.networkValue', { network: request.officeNetwork })
          : request.place
            ? t(`lab.place.${request.place}`)
            : '-',
      changed: changes.includes('place'),
    },
    {
      key: 'device',
      label: t('show.console.device'),
      value:
        request.device === 'USUAL'
          ? t('show.console.deviceValue', { device: baseline.data?.learned.devices.join(' · ') || '-' })
          : request.device
            ? t(`lab.device.${request.device}`)
            : '-',
      changed: changes.includes('device'),
    },
    {
      key: 'approval',
      label: t('show.console.approval'),
      value: approvalText,
      changed: changes.includes('approval'),
    },
    {
      key: 'target',
      label: t('show.console.target'),
      value: t('show.console.targetValue', {
        project: request.project ?? '-',
        target: request.target ? t(`lab.target.${request.target}`) : '-',
        operation: t(`lab.operation.${request.operation}`),
        items: request.items === null ? '-' : request.items.toLocaleString(i18n.language),
      }),
      changed: changes.includes('target'),
    },
  ];

  // Contexa holds the attacker with a check the attacker cannot pass (the code goes to the employee's mailbox) or with a
  // block: the run waits for it, and the attacker's screen says so whichever request was held.
  const release = view?.release ?? null;
  const attackerHeld =
    role === 'attacker' && (view?.status === 'CHALLENGE' || view?.status === 'BLOCKED' || release !== null);
  const retryMeta =
    second.D.kind === 'done'
      ? t('show.retryResult.meta', {
          status: second.D.httpStatus ?? '—',
          seconds: secondsText(second.D.elapsedMs),
        })
      : undefined;
  const lock =
    role !== 'attacker'
      ? null
      : release?.stage === 'NO_MAILBOX'
        ? {
            title: t('show.lock.NO_MAILBOX'),
            detail: t('show.lock.NO_MAILBOXDetail', { name: request.employeeName }),
            ...(retryMeta ? { meta: retryMeta } : {}),
          }
        : release
          ? {
              title: t('show.lock.BLOCK'),
              detail: t('show.lock.BLOCKDetail'),
              ...(retryMeta ? { meta: retryMeta } : {}),
              ...(release.stage === 'BLOCKED'
                ? {
                    action: (
                      <button
                        type="button"
                        className={consoleStyles.lockAction}
                        onClick={() => void act('/api/live/runs/current/release-start')}
                      >
                        {t('show.release.attackerTry')}
                      </button>
                    ),
                  }
                : {}),
            }
          : retry && HOLDING.has(retry) && second.D.kind === 'done'
            ? {
                title: t(`show.lock.${retry}`),
                detail: t(`show.lock.${retry}Detail`, { name: request.employeeName }),
                ...(retryMeta ? { meta: retryMeta } : {}),
              }
            : attackerHeld
              ? {
                  title: t('show.lock.CHALLENGE'),
                  detail: t('show.lock.CHALLENGEDetail', { name: request.employeeName }),
                }
              : null;

  // The attacker moves on once the hold showed on a second try, or at once when Contexa held nothing; the real
  // owner once the work and any check of it ended.
  const canMoveOn =
    firstDone &&
    (role === 'owner'
      ? view?.status !== 'CHALLENGE' && view?.status !== 'BLOCKED'
      : attackerHeld ||
        retry !== null ||
        (settled && !(engine && HOLDING.has(engine.action))) ||
        (!viewActive && !secondSent));
  const resumed =
    role === 'owner' && view?.challenge?.stage === 'DONE' && view.challenge.reissueOutcome === 'DELIVERED'
      ? view.challenge
      : null;
  const released =
    role === 'owner' && release?.stage === 'DONE' && release.reissueOutcome === 'DELIVERED' ? release : null;
  // The marks of the lanes are the server's score over the steps shown so far, read once per stage of the run.
  const secondDone = secondSent && CONTROL_ORDER.every((control) => second[control].kind === 'done');
  const scoredSteps = secondDone ? 2 : firstDone ? 1 : 0;
  const scoreStage =
    scoredSteps === 0
      ? null
      : [scoredSteps, resumed ? 'resumed' : '', released ? 'released' : '', view?.status ?? ''].join(':');
  const runScore = useRunScore(view?.runId ?? null, scoreStage, scoredSteps);
  const score = runScore.data && runScore.data.executedSteps >= scoredSteps ? runScore.data : null;

  const failed = view !== null && (view.status === 'FAILED' || view.status === 'EXPIRED');
  const phase = attempt?.liveRunId ? 'live' : 'ready';
  // What the engine was told about the first request, from its stored anatomy once the run ended (5A.3).
  const anatomy = useAnatomy(viewEnded && engine !== null ? (view?.runId ?? null) : null, 1);
  const received =
    anatomy.data && anatomy.data.interpretation.recorded.finalAction ? anatomy.data.context.usualVsNow : null;

  return (
    <div className={styles.scene} data-phase={phase} data-role={role}>
      <header className={styles.head}>
        <h1 className={styles.title} tabIndex={-1}>
          {t(role === 'attacker' ? 'show.attacker.title' : 'show.owner.title', {
            name: request.employeeName,
          })}
        </h1>
        <p className={styles.lead}>
          {t(
            role === 'attacker' ? 'show.attacker.lead' : approval ? 'show.owner.lead' : 'show.owner.leadNone',
            {
              ...approvalFacts,
              role: t(`lab.role.${request.role}`),
              target: request.target ? t(`lab.target.${request.target}`) : '-',
              project: request.project ?? '-',
              items: request.items === null ? '-' : request.items.toLocaleString(i18n.language),
            },
          )}
        </p>
        {previous ? (
          <p className={styles.changed}>
            <span className={styles.changedTag}>{t('show.owner.changed')}</span>
            {changes.length === 0
              ? t('show.owner.noChange')
              : changes.map((change) => t(`show.change.${change}`)).join(' · ')}
            {changes.includes('approval') ? ` · ${approvalText}` : ''}
          </p>
        ) : null}
        <details className={styles.why}>
          <summary>{t(role === 'attacker' ? 'show.why.attacker' : 'show.why.owner')}</summary>
          <p>{t(role === 'attacker' ? 'show.why.attackerMore' : 'show.why.ownerMore')}</p>
        </details>
      </header>

      {phase === 'live' ? (
        <div className={styles.conclusion}>
          <SceneConclusion
            headline={
              released
                ? {
                    text: t('show.conclusion.released', {
                      seconds: released.reissueSentMs === null ? '—' : secondsText(released.reissueSentMs),
                    }),
                    tone: 'safe',
                  }
                : resumed
                  ? {
                      text: t('show.conclusion.resumed', {
                        seconds: resumed.reissueSentMs === null ? '—' : secondsText(resumed.reissueSentMs),
                      }),
                      tone: 'safe',
                    }
                  : ending
                    ? headlineOf(ending, t)
                    : null
            }
            waiting={waitingText(view, t)}
            details={
              released
                ? [
                    { text: t('show.conclusion.releasedDetail') },
                    ...(ending ? detailsOf(ending, role, engine, first, firstDone, total, t).slice(-1) : []),
                  ]
                : resumed
                  ? [
                      { text: t('show.conclusion.resumedDetail') },
                      ...(ending
                        ? detailsOf(ending, role, engine, first, firstDone, total, t).slice(-1)
                        : []),
                    ]
                  : ending
                    ? detailsOf(ending, role, engine, first, firstDone, total, t)
                    : []
            }
          />
        </div>
      ) : null}

      {phase === 'live' && role === 'attacker' ? (
        <div className={styles.counters}>
          <LeakCounters
            existing={leakedThroughExisting(first)}
            contexa={first.D}
            total={total}
            // Only an answer Contexa itself stopped or cut counts; a stream that broke after every item left
            // (BROKEN) or an unresolved answer is not a stop.
            stopped={
              first.D.kind === 'done' &&
              (first.D.outcome === 'CUT' || first.D.outcome === 'STOPPED' || first.D.outcome === 'HELD')
            }
          />
        </div>
      ) : null}

      {attempt?.refusal || failed || (role === 'owner' && (view?.challenge || release)) ? (
        <div className={styles.state}>
          {attempt?.refusal ? (
            <StateScreen
              kind={
                attempt.refusal === 'dailyLimit'
                  ? 'dailyLimit'
                  : attempt.refusal === 'paused'
                    ? 'paused'
                    : 'outage'
              }
              recordTo="/benchmark"
              {...(attempt.refusal === 'error' ? { onRetry: () => void send() } : {})}
            />
          ) : null}
          {failed ? <StateScreen kind="outage" onRetry={() => void send()} /> : null}
          {role === 'owner' && view?.challenge ? (
            <LiveChallenge
              challenge={view.challenge}
              onRequestCode={() => void act('/api/live/runs/current/code')}
              onAnswer={(code) => void act('/api/live/runs/current/answer', { code })}
              onCancel={() => void act('/api/live/runs/current/cancel')}
              onRestart={() => void send()}
            />
          ) : null}
          {role === 'owner' && release && (release.stage === 'FAILED' || release.stage === 'EXPIRED') ? (
            <StateScreen
              kind="recoveryFailed"
              onRetry={() => void send()}
              {...(release.cause ? { cause: release.cause } : {})}
            />
          ) : null}
          {role === 'owner' &&
          release &&
          release.stage !== 'DONE' &&
          release.stage !== 'FAILED' &&
          release.stage !== 'EXPIRED' &&
          release.stage !== 'ABANDONED' ? (
            <ReleasePanel
              release={release}
              defaultReason={t('show.release.reasonDefault', {
                ...approvalFacts,
                approver: approval?.approver ?? '-',
                max:
                  approval?.maxItems === null || approval === null
                    ? '-'
                    : approval.maxItems.toLocaleString(i18n.language),
              })}
              onStart={() => void act('/api/live/runs/current/release-start')}
              onAnswer={(code) => void act('/api/live/runs/current/answer', { code })}
              onRequest={(reason) => void act('/api/live/runs/current/release-request', { reason })}
              onApprove={() => void act('/api/live/runs/current/release-approve')}
            />
          ) : null}
        </div>
      ) : null}

      {phase === 'live' ? (
        <div className={styles.analysis}>
          <AnalysisPanel
            role={role}
            working={analysisRunning && !settled && !noNewAnalysis}
            noNewAnalysis={noNewAnalysis && stages.length === 0}
            stages={stages}
          />
        </div>
      ) : null}

      <div className={styles.console}>
        <RoleConsole role={role} name={request.employeeName} rows={rows} lock={lock}>
          {turnstileRequired ? <div ref={turnstileContainer} hidden={attempt?.liveRunId != null} /> : null}
          {!attempt?.liveRunId ? (
            <>
              <fieldset className={styles.predict}>
                <legend>{t(role === 'attacker' ? 'show.predict.attacker' : 'show.predict.owner')}</legend>
                {(['YES', 'NO', 'UNSURE'] as const).map((value) => (
                  <label
                    key={value}
                    className={styles.predictChoice}
                    data-selected={prediction === value || undefined}
                  >
                    <input
                      type="radio"
                      name={`predict-${role}`}
                      checked={prediction === value}
                      onChange={() => setPrediction(value)}
                    />
                    {t(`show.predict.${value}`)}
                  </label>
                ))}
              </fieldset>
              {prediction === null ? <p className={styles.note}>{t('show.predict.first')}</p> : null}
              <button
                type="button"
                className={styles.send}
                disabled={!ready || otherActive || attempt?.sending === true}
                onClick={() => void send()}
              >
                {otherActive
                  ? t('show.next.wait')
                  : t(role === 'attacker' ? 'show.attacker.send' : 'show.owner.send', {
                      project: request.project ?? '-',
                      items: request.items === null ? '-' : request.items.toLocaleString(i18n.language),
                    })}
              </button>
              <p className={styles.note}>
                {gate.remainingToday !== null
                  ? t('exp.console.note', { remaining: gate.remainingToday })
                  : ''}
              </p>
            </>
          ) : null}
          {awaitingRetry || retrying ? (
            <>
              <button
                type="button"
                className={styles.send}
                disabled={retrying}
                onClick={() => void act('/api/live/runs/current/next')}
              >
                {retrying ? t('show.attacker.retrying') : t('show.attacker.retry', followUpText)}
              </button>
              <p className={styles.note}>{t('show.attacker.retryNote')}</p>
            </>
          ) : null}
          {retry === 'PASSED' || retry === 'OTHER' ? (
            <p className={styles.retryResult} data-tone={retry === 'PASSED' ? 'loss' : 'idle'}>
              {t(`show.retryResult.${retry}`)}
              {second.D.kind === 'done'
                ? ` · ${t('show.lane.meta', {
                    status: second.D.httpStatus ?? '—',
                    seconds: secondsText(second.D.elapsedMs),
                  })}`
                : ''}
            </p>
          ) : null}
        </RoleConsole>
      </div>

      <div className={styles.baseline}>
        {baseline.data ? (
          <BaselinePanel
            baseline={baseline.data}
            request={request}
            received={received}
            differences={role === 'owner' ? 'plain' : 'alert'}
          />
        ) : null}
        {baseline.isError ? <StateScreen kind="notReady" /> : null}
      </div>

      {phase === 'live' ? (
        <div className={styles.lanes}>
          <ApproachStrip
            role={role}
            lanes={first}
            total={total}
            resumedItems={
              released
                ? released.reissueDeliveredItems
                : resumed
                  ? (resumed.reissueDeliveredItems ?? null)
                  : null
            }
            resumedBy={released ? 'release' : 'check'}
            score={secondSent ? null : score}
          />
          {view?.runId && firstDone ? (
            <Link className={styles.anatomyLink} to={`/runs/${view.runId}/steps/1`}>
              {t('show.openAnatomy')}
            </Link>
          ) : null}
          {prediction && score?.business['D'] ? (
            <p className={styles.callResult}>
              {t('show.predict.result', {
                call: t(`show.predict.${prediction}`),
                actual: t(`score.result.${score.business['D'].result}`, {
                  n: score.business['D'].exposedItems.toLocaleString(i18n.language),
                  count: score.business['D'].exposedItems,
                }),
              })}
            </p>
          ) : null}
          {secondSent ? (
            <ApproachStrip
              role={role}
              lanes={second}
              total={1}
              title={t('show.lanes.retryTitle', followUpText)}
              headingId="retry-approaches-title"
              score={secondDone ? score : null}
            />
          ) : null}
        </div>
      ) : null}

      {canMoveOn && view?.runId ? (
        <div className={styles.assess}>
          <AssessPanel runId={view.runId} reasons={assessmentReasons} />
        </div>
      ) : null}

      <nav className={styles.next} aria-label={t('show.act.label')}>
        {canMoveOn ? (
          <button type="button" className={styles.primary} onClick={onNext}>
            {t(role === 'attacker' ? 'show.next.owner' : 'show.next.adopt')}
          </button>
        ) : null}
      </nav>
    </div>
  );
}

/** The fields of the second act's request that differ from the first's, as their cases define them. */
function differences(before: SceneRequest, now: SceneRequest): string[] {
  const list: string[] = [];
  if (before.time !== now.time) {
    list.push('time');
  }
  if (before.place !== now.place) {
    list.push('place');
  }
  if (before.device !== now.device) {
    list.push('device');
  }
  if (before.project !== now.project || before.items !== now.items || before.operation !== now.operation) {
    list.push('target');
  }
  if ((before.approval === null) !== (now.approval === null)) {
    list.push('approval');
  }
  return list;
}

function waitingText(view: LiveRunView | null, t: TFunction): string {
  if (view?.status === 'QUEUED') {
    return t('show.queued', { n: view.queuePosition });
  }
  if (view === null || view.status === 'STARTING') {
    return t('show.preparing');
  }
  return t('show.conclusion.waiting');
}

function seconds(engine: EngineDecision | null): string {
  return engine?.atMs != null ? secondsText(engine.atMs) : '—';
}

function headlineOf(ending: Conclusion, t: TFunction): ConclusionLine {
  switch (ending.kind) {
    case 'cut':
      return { text: t('show.conclusion.cut', { n: ending.delivered.toLocaleString() }), tone: 'contexa' };
    case 'stopped':
      return {
        text: t('show.conclusion.stopped', { n: ending.delivered.toLocaleString(), count: ending.delivered }),
        tone: 'safe',
      };
    case 'leakedThenLocked':
      return {
        text: t('show.conclusion.leakedThenLocked', { action: t(`show.action.${ending.action}`) }),
        tone: 'loss',
      };
    case 'missed':
      return { text: t('show.conclusion.missed'), tone: 'loss' };
    case 'completed':
      return { text: t('show.conclusion.completed', { n: ending.delivered.toLocaleString() }), tone: 'safe' };
    case 'halted':
      return { text: t('show.conclusion.halted'), tone: 'halt' };
    case 'checked':
      return { text: t('show.conclusion.checked'), tone: 'contexa' };
    default:
      return { text: t('show.conclusion.unresolved'), tone: 'idle' };
  }
}

function detailsOf(
  ending: Conclusion,
  role: Role,
  engine: EngineDecision | null,
  first: Readonly<Record<ControlId, LaneState>>,
  firstDone: boolean,
  total: number,
  t: TFunction,
): ConclusionLine[] {
  const lines: ConclusionLine[] = [];
  if (ending.kind === 'cut') {
    lines.push({
      text: t('show.conclusion.cutDetail', {
        seconds: seconds(engine),
        n: ending.delivered.toLocaleString(),
      }),
    });
  } else if (ending.kind === 'leakedThenLocked') {
    lines.push({ text: t('show.conclusion.leakedThenLockedDetail', { seconds: seconds(engine) }) });
  } else if (ending.kind === 'missed') {
    lines.push({
      text: engine
        ? t('show.conclusion.missedDetail', {
            n: ending.delivered.toLocaleString(),
            action: t(`show.action.${engine.action}`),
            seconds: seconds(engine),
          })
        : t('show.lane.leaked', { n: ending.delivered.toLocaleString() }),
    });
  }
  if (!firstDone) {
    return lines;
  }
  const others = CONTROL_ORDER.filter((control) => control !== 'D');
  if (role === 'attacker') {
    const existing = leakedThroughExisting(first);
    if (existing > 0) {
      // "All" only when the existing security let every announced item out (#16).
      lines.push({
        text: t(existing >= total ? 'show.conclusion.existingAll' : 'show.conclusion.existing', {
          n: existing.toLocaleString(),
        }),
        tone: 'loss',
      });
    }
    // Passed counts only what was delivered; a failed request or an unresolved answer is neither (#14).
    const stopped = others.filter((control) => passedOf(first[control]) === false).length;
    const passed = others.filter((control) => passedOf(first[control]) === true).length;
    lines.push({
      text: t('show.conclusion.others', { stopped, passed, other: others.length - stopped - passed }),
    });
  } else {
    const halted = others.filter((control) => passedOf(first[control]) === false);
    const passed = others.filter((control) => passedOf(first[control]) === true).length;
    if (halted.length > 0) {
      lines.push({
        text: t('show.conclusion.ownerHalted', {
          list: halted.map((control) => t(`control.${control}.name`)).join(', '),
        }),
        tone: 'halt',
      });
    } else if (passed === others.length) {
      lines.push({ text: t('show.conclusion.ownerNone') });
    } else {
      // "All passed" only when every other approach delivered; an unresolved answer is counted apart (#15).
      lines.push({
        text: t('show.conclusion.others', { stopped: 0, passed, other: others.length - passed }),
      });
    }
  }
  return lines;
}

function passedOf(lane: LaneState): boolean | null {
  if (lane.kind !== 'done' || lane.outcome === 'UNRESOLVED') {
    return null;
  }
  return lane.outcome === 'DELIVERED';
}
