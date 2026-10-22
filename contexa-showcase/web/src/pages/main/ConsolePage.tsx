import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useAnatomy, useBeforeSend, useReceived } from '../../api/anatomy';
import { useBenchmark } from '../../api/benchmark';
import { postJson } from '../../api/http';
import { useLabOptions, type LabCase } from '../../api/lab';
import { usePublicSettings } from '../../api/settings';
import { useTeasers } from '../../api/teasers';
import type { LiveRunView } from '../../api/types';
import { useDetail } from '../../components/detail/useDetail';
import { LiveChallenge } from '../../components/LiveChallenge';
import { Chip } from '../../components/main/Chip';
import { GhostButton, MainLink, MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { ReleasePanel } from '../../components/show/ReleasePanel';
import { StateScreen } from '../../components/StateScreen';
import { CONTROL_ORDER, type ControlId } from '../../domain/verdict';
import { count, seconds } from '../../journey/format';
import { useTryAnalysis, useTryRun } from '../try/steps/tryRun';
import {
  atSeconds,
  callLines,
  contexaGaveKnown,
  eventLine,
  factRows,
  hasSecondPass,
  repeatLabel,
  riskText,
} from './consoleData';
import { CompareStrip, FactMark, Lane } from './consoleParts';
import { StepRow } from './RequestSteps';
import {
  caseOf,
  KEEPS_IN,
  MAIN_CASES,
  personName,
  PRIOR_REFUSALS,
  readsAgain,
  ROLE_NUMBERS,
  ROLE_PATHS,
  verdictChip,
  type Role,
} from './mainCases';
import checkStyles from './CheckPage.module.css';
import styles from './ConsolePage.module.css';
import { useCountUp } from './useCountUp';

/** The run states during which the console still follows the run. */
const GOING = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED']);

/**
 * 2-2, 4-2 and 5-2, the live decision console (설계서 2-2, 4-2; IN-6 for the insider): the same request at five
 * approaches at once; a case of several requests (the insider's three documents) shows one row per request instead of
 * the lanes, so a decision applied from the next request on is seen where it took effect. Each lane
 * fills with its real answer (HTTP status, response time, items handed over) as it arrives; Contexa's lane holds the
 * response while the engine decides. On the right the facts the engine compared, its risk score and tokens, and its
 * own event log line by line; the data the existing security let out stands against what Contexa let out, and the
 * stop is stamped once the engine applied it. A real user who meets an extra check answers it here and the request
 * goes on. Every value is the run's own record; nothing is made up on the screen. Once the run is stored, its log is
 * read from the stored record, so the same run shows the same times on every visit and in every language (V-20).
 * A case of several requests names the request its facts, risk and log belong to (V-02). While Contexa decides, the
 * risk score's place says so, and the footer says once what the waiting button waits for (L-30).
 */
export default function ConsolePage({ role }: { readonly role: Role }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const detail = useDetail();
  const key = MAIN_CASES[role];
  const number = ROLE_NUMBERS[role].console;
  // The owner and the insider hold the account's mailbox: an extra check's code is theirs to read (IN-6).
  const holdsMailbox = role !== 'attacker';
  const options = useLabOptions();
  const found = caseOf(options.data, key);
  const steps = found?.labCase.steps ?? 1;
  const multi = steps > 1;
  const run = useTryRun(key, steps);
  const view: LiveRunView | null = run.view;
  const layers = view?.steps.find((step) => step.stepNo === 1)?.layers ?? {};
  const lastLayers = view?.steps.find((step) => step.stepNo === steps)?.layers ?? {};
  const analysis = useTryAnalysis(view, run.stored);
  const decision = analysis.decision;
  const contexa = layers.D ?? null;
  // Every request answered: the one request, or for several the last one (or the run ended before it).
  const allAnswered =
    CONTROL_ORDER.every((control) => (multi ? lastLayers : layers)[control] !== undefined) ||
    (multi && view?.status === 'COMPLETED');
  const going = view !== null && GOING.has(view.status);
  const challenge = view?.challenge ?? null;
  const release = view?.release ?? null;
  // Done once all five answered and the decision is in; a real user's extra check or release is done once the
  // request went on or the way ended.
  const checkOpen =
    holdsMailbox && challenge !== null && !['DONE', 'NO_MAILBOX', 'ABANDONED'].includes(challenge.stage);
  const releaseOpen = role === 'owner' && release !== null && !RELEASE_ENDED.has(release.stage);
  // A request a decision already in force refused has no decision of its own; the run's end is its end.
  const refusedEarlier = PRIOR_REFUSALS.has(contexa?.ruleId ?? '') && view?.status === 'COMPLETED';
  const done =
    allAnswered && (decision !== null || analysis.missing || refusedEarlier) && !checkOpen && !releaseOpen;
  const runId = view?.runId ?? null;
  // The run's own records are read once the portal has stored them (its company facts come with the stored step).
  const recorded = done && (run.stored || view?.status === 'COMPLETED');
  const received = useReceived(recorded ? runId : null, 1);
  const anatomy = useAnatomy(recorded ? runId : null, 1);
  // The stored record's analysis of a run followed live, once the portal has stored it (V-20).
  const storedAnalysis = useTryAnalysis(recorded && !run.stored ? view : null, true);
  const before = useBeforeSend(key, 1);
  const comparison = received.data ?? before.data?.comparison ?? null;
  const own = received.data !== undefined;
  const benchmark = useBenchmark(null);
  const measured = benchmark.data?.cases.find((candidate) => candidate.key === key) ?? null;
  const settings = usePublicSettings();
  const teasers = useTeasers();
  const threat = found?.labCase.classification === 'THREAT';
  const asked = useRef<string | null>(null);
  const triedRelease = useRef<string | null>(null);

  // An attacker who meets an extra check asks for the code at once; it goes to the real user's mailbox.
  useEffect(() => {
    if (
      role === 'attacker' &&
      view?.status === 'CHALLENGE' &&
      view.challenge?.stage === 'WAITING' &&
      asked.current !== view.liveRunId
    ) {
      asked.current = view.liveRunId;
      void act('/api/live/runs/current/code');
    }
    // `act` is recreated on every render; the run's state is what matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [role, view?.status, view?.challenge?.stage, view?.liveRunId]);

  // An attacker whose account the engine blocked asks for the release at once (FU-1): the check it needs sends its
  // code to the real user's mailbox, so the attempt ends there and the block stays.
  useEffect(() => {
    if (
      role === 'attacker' &&
      view?.status === 'BLOCKED' &&
      view.release?.stage === 'BLOCKED' &&
      triedRelease.current !== view.liveRunId
    ) {
      triedRelease.current = view.liveRunId;
      void act('/api/live/runs/current/release-start');
    }
    // `act` is recreated on every render; the run's state is what matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [role, view?.status, view?.release?.stage, view?.liveRunId]);

  async function act(path: string, body: Record<string, string> = {}) {
    const response = await postJson<LiveRunView>(path, body);
    if (response.body && response.status < 300) {
      queryClient.setQueryData(['live-run'], response.body);
    }
  }

  const legacy = layers.B ?? null;
  // The items each side let out over all the requests sent so far (one request: its own answer).
  const handed = (control: ControlId) =>
    (view?.steps ?? []).reduce((sum, step) => sum + (step.layers[control]?.deliveredItems ?? 0), 0);
  const legacyItems = useCountUp(legacy ? (multi ? handed('B') : legacy.deliveredItems) : null);
  const contexaItems = useCountUp(
    contexa && contexaGaveKnown(contexa, decision !== null && decision !== undefined)
      ? multi
        ? handed('D')
        : contexa.deliveredItems
      : null,
  );
  const title = t(`main.${number}.title`);

  if (run.pending || options.isPending) {
    return (
      <MainScreen title={title} main={null}>
        <StateScreen kind="loading" />
      </MainScreen>
    );
  }
  if (view === null) {
    return (
      <MainScreen
        title={title}
        intro={t('main.console.notSent')}
        main={<MainLink to={ROLE_PATHS[role].request}>{t('main.console.toRequest')}</MainLink>}
        nextNote={null}
      >
        {null}
      </MainScreen>
    );
  }
  if (view.status === 'FAILED' || view.status === 'EXPIRED') {
    return (
      <MainScreen
        title={title}
        intro={t('main.console.failed')}
        main={<MainLink to={ROLE_PATHS[role].request}>{t('main.console.retry')}</MainLink>}
        nextNote={null}
      >
        <StateScreen kind="outage" recordTo="/" />
      </MainScreen>
    );
  }

  const threshold = settings.data?.threshold ?? null;
  const subs: Readonly<Record<ControlId, string>> = {
    A: t('main.lane.A.sub'),
    B: t('main.lane.B.sub'),
    C1:
      threshold && threshold.nightStart && threshold.nightEnd && threshold.volumeLimit !== null
        ? t('main.lane.C1.sub', {
            start: threshold.nightStart,
            end: threshold.nightEnd,
            limit: count(threshold.volumeLimit, language),
          })
        : t('main.lane.C1.subPlain'),
    C2: t('main.lane.C2.sub'),
    D: t('main.lane.D.sub'),
  };
  const facts = comparison ? factRows(t, comparison) : [];
  const stages = storedAnalysis.stages ?? analysis.stages ?? [];
  const secondPass = hasSecondPass(stages);
  const lit = run.stored || decision !== null || stages.some((stage) => stage.type === 'CONTEXT_COLLECTED');
  const verdict = decision ? verdictChip(decision) : null;
  const stamped =
    done &&
    decision !== null &&
    KEEPS_IN.has(decision.finalAction) &&
    (multi ? handed('D') : (contexa?.deliveredItems ?? 1)) === 0;
  // The engine's events as they arrive and, once the run is recorded, each model call's answer after the event the
  // record lists before it.
  const calls = callLines(t, anatomy.data ?? null, language);
  const callsAfter = (events: number) =>
    calls
      .filter((call) => call.after === events || (events === stages.length && call.after > events))
      .map((call) => ({ key: call.key, at: '', text: call.text, tone: 'ai' as const }));
  const log = [
    ...callsAfter(0),
    ...stages.flatMap((stage, index) => {
      const line = eventLine(t, stage, {
        anatomy: anatomy.data ?? null,
        contexa,
        decision,
        language,
        secondPass,
      });
      return [
        ...(line
          ? [{ key: `event-${index}`, at: atSeconds(t, stage.atMs), text: line.text, tone: line.tone }]
          : []),
        ...callsAfter(index + 1),
      ];
    }),
  ];
  const resumed = teasers.data?.teasers.find((teaser) => teaser.key === 'CHALLENGE_OUTCOMES')?.values[
    'resumed'
  ];

  return (
    <MainScreen
      title={title}
      // What the bars are, read before the lanes fill (B-03); a case of several requests shows rows, not bars.
      intro={multi ? null : t(threat ? 'main.console.guide.threat' : 'main.console.guide.normal')}
      live={going && runId ? runId : null}
      // The next screens read the stored run (its records, the visitor's list of runs), so the way on opens once
      // the portal has stored it, a moment after the decision.
      waiting={
        recorded
          ? null
          : done
            ? { label: t('main.console.storing'), hint: t('main.console.storingHint') }
            : { label: t('main.console.deciding'), hint: t('main.console.decidingHint') }
      }
      extra={
        done && runId ? (
          <GhostButton onClick={() => detail.show(runId, 1, 'original')}>{t('main.console.raw')}</GhostButton>
        ) : null
      }
    >
      {view.status === 'QUEUED' ? (
        <StateScreen
          kind="queued"
          queuePosition={view.queuePosition}
          remainingSeconds={view.queueWaitSeconds}
        />
      ) : null}
      <div className={styles.console}>
        <div className={styles.column}>
          <section className={styles.card} aria-label={t('main.console.lanes')}>
            {multi && found ? (
              <ol className={checkStyles.steps}>
                {found.labCase.requests.map((request, index) => (
                  <StepRow
                    key={index}
                    stepNo={index + 1}
                    request={request}
                    facts={found.labCase.facts}
                    view={view}
                    stored={run.stored}
                    runId={recorded ? runId : null}
                    threat={threat}
                    language={language}
                    again={readsAgain(found.labCase.requests, index)}
                  />
                ))}
              </ol>
            ) : (
              <ul className={styles.lanes}>
                {CONTROL_ORDER.map((control) => (
                  <Lane
                    key={control}
                    control={control}
                    sub={subs[control]}
                    layer={layers[control] ?? null}
                    threat={threat}
                    decision={decision}
                    holding={control === 'D'}
                    wait={control === 'D' ? analysis.wait : null}
                  />
                ))}
              </ul>
            )}
          </section>
          <section
            className={styles.leak}
            aria-label={t('main.console.leak')}
            data-threat={threat || undefined}
          >
            <div className={styles.counter}>
              <p className={styles.counterLabel}>
                {t(threat ? 'main.console.leaked' : 'main.console.handedOver')}
              </p>
              <p className={styles.counterValue} data-tone={threat ? 'leak' : 'pass'} aria-live="polite">
                {legacyItems === null
                  ? '…'
                  : t('main.items', { count: legacyItems, items: count(legacyItems, language) })}
              </p>
            </div>
            <div className={styles.counter}>
              <p className={styles.counterLabel}>{t('main.console.contexaGave')}</p>
              <p
                className={styles.counterValue}
                data-tone={contexaItems === null ? 'idle' : contexaItems > 0 ? 'pass' : 'safe'}
                aria-live="polite"
              >
                {contexaItems === null
                  ? t('main.console.holding')
                  : t('main.items', { count: contexaItems, items: count(contexaItems, language) })}
              </p>
            </div>
            {stamped && verdict ? (
              <span className={styles.stamp} data-kind={verdict.kind} role="img" aria-label={t(verdict.key)}>
                {t(decision?.finalAction === 'CHALLENGE' ? 'main.stamp.auth' : 'main.stamp.block')}
              </span>
            ) : null}
          </section>
        </div>
        <div className={styles.column}>
          <section className={styles.card} data-active={!done || undefined} aria-labelledby="facts-title">
            <div className={styles.factsHead}>
              <h2 id="facts-title" className={styles.factsTitle}>
                {t('main.facts.title')}
                {multi ? <span className={styles.stepTag}>{t('main.console.stepOf', { n: 1 })}</span> : null}
              </h2>
              {comparison ? (
                <SourceBadge
                  kind={own ? 'run' : 'repeated'}
                  label={t(own ? 'main.facts.sourceOwn' : 'main.facts.sourceLatest')}
                  runId={comparison.runId}
                />
              ) : (
                <span className={styles.factsNote}>{t('main.facts.input')}</span>
              )}
            </div>
            {/* Before the run is stored the facts are the latest run's: faint, and named as a reference (B-03). */}
            {comparison && !own ? <p className={styles.staleNote}>{t('main.facts.stale')}</p> : null}
            {comparison ? (
              <div className={styles.factsBody} data-stale={!own || undefined}>
                <CompareStrip
                  rows={comparison.usualVsNow}
                  departures={comparison.departureCount}
                  compared={comparison.comparedCount ?? null}
                />
              </div>
            ) : null}
            <ul className={styles.facts} data-stale={(comparison !== null && !own) || undefined}>
              {facts.map((fact, index) => (
                <li
                  key={fact.id}
                  className={styles.fact}
                  data-lit={lit || undefined}
                  style={{ animationDelay: `calc(var(--motion-fact) * ${index})` }}
                >
                  <b className={styles.factName}>{fact.name}</b>
                  <div className={styles.factValue}>
                    <b>{fact.now}</b>
                    <span className={styles.factAgainst}>{fact.against}</span>
                  </div>
                  <FactMark mark={fact.mark} lit={lit} />
                </li>
              ))}
            </ul>
            <div className={styles.risk}>
              <div className={styles.riskHead}>
                <span className={styles.riskLabel}>{t('main.console.risk')}</span>
                <b
                  className={styles.riskValue}
                  data-waiting={(decision?.riskScore == null && !done) || undefined}
                >
                  {riskText(t, decision?.riskScore, done)}
                </b>
              </div>
              <span className={styles.riskTrack} aria-hidden="true">
                <span
                  className={styles.riskFill}
                  style={{ inlineSize: `${Math.round((decision?.riskScore ?? 0) * 100)}%` }}
                />
              </span>
              <p className={styles.riskNote}>
                {decision
                  ? t('main.console.tokens', {
                      calls: decision.modelCalls,
                      input: count(decision.promptTokens, language),
                      output: count(decision.completionTokens, language),
                    })
                  : analysis.wait
                    ? t('main.console.usualTime', { seconds: seconds(analysis.wait.medianMs) })
                    : t('main.console.waitingModel')}
              </p>
            </div>
            {done && measured ? (
              <div className={styles.factsSource}>
                <SourceBadge kind="repeated" label={repeatLine(t, measured.runs, measured.engineActions)} />
              </div>
            ) : null}
          </section>
          <section className={styles.log} aria-label={t('main.console.events')}>
            {multi ? <p className={styles.logHead}>{t('main.console.stepOf', { n: 1 })}</p> : null}
            {found ? (
              <p className={styles.logLine}>
                <span className={styles.logAt}>{atSeconds(t, 0)}</span>
                <span>{t('main.event.received', { name: personName(t, found.employee) })}</span>
              </p>
            ) : null}
            {log.map((entry) => (
              <p key={entry.key} className={styles.logLine} data-tone={entry.tone}>
                <span className={styles.logAt}>{entry.at}</span>
                <span>{entry.text}</span>
              </p>
            ))}
            {!done && going ? <p className={styles.logCursor} aria-hidden="true" /> : null}
          </section>
        </div>
      </div>
      {holdsMailbox && challenge ? (
        <section className={styles.recovery} aria-labelledby="recovery-title">
          <h2 id="recovery-title" className={styles.recoveryTitle}>
            {t('main.recovery.title')}
          </h2>
          <ol className={styles.recoverySteps}>
            {recoverySteps(challenge.stage).map((step, index) => (
              <li key={step.id} className={styles.recoveryStep} data-state={step.state}>
                <span className={styles.recoveryNumber}>{t('main.recovery.step', { n: index + 1 })}</span>
                <b className={styles.recoveryName}>{t(`main.recovery.${step.id}`)}</b>
                {step.id === 'retry' && challenge.reissueDoneMs !== null ? (
                  <Chip kind="allow">
                    {t('main.recovery.retried', {
                      count: challenge.reissueDeliveredItems ?? 0,
                      items: count(challenge.reissueDeliveredItems ?? 0, language),
                      status: challenge.reissueStatus ?? '—',
                    })}
                  </Chip>
                ) : null}
              </li>
            ))}
          </ol>
          <LiveChallenge
            challenge={challenge}
            onRequestCode={() => void act('/api/live/runs/current/code')}
            onAnswer={(code) => void act('/api/live/runs/current/answer', { code })}
            onCancel={() => void act('/api/live/runs/current/cancel')}
            onRestart={() => void navigate(ROLE_PATHS[role].request)}
          />
          {typeof resumed === 'number' ? (
            <SourceBadge
              kind="repeated"
              label={t('main.recovery.measured', { n: count(resumed, language) })}
            />
          ) : null}
        </section>
      ) : null}
      {role === 'attacker' && release?.stage === 'NO_MAILBOX' ? (
        <section className={styles.recovery} aria-labelledby="release-title">
          <h2 id="release-title" className={styles.recoveryTitle}>
            {t('main.release.attacker')}
          </h2>
        </section>
      ) : null}
      {role === 'owner' && release ? (
        <section className={styles.recovery} aria-labelledby="release-way-title">
          <h2 id="release-way-title" className={styles.recoveryTitle}>
            {t('main.release.title')}
          </h2>
          {release.stage === 'DONE' ? (
            <Chip kind="allow">
              {t('main.release.done', {
                count: release.reissueDeliveredItems ?? 0,
                items: count(release.reissueDeliveredItems ?? 0, language),
                status: release.reissueStatus ?? '—',
              })}
            </Chip>
          ) : release.stage === 'FAILED' || release.stage === 'EXPIRED' ? (
            <StateScreen
              kind="recoveryFailed"
              onRetry={() => void navigate(ROLE_PATHS[role].request)}
              {...(release.cause ? { cause: release.cause } : {})}
            />
          ) : release.stage !== 'ABANDONED' && release.stage !== 'NO_MAILBOX' ? (
            <ReleasePanel
              release={release}
              defaultReason={releaseReason(t, language, found?.labCase ?? null)}
              onStart={() => void act('/api/live/runs/current/release-start')}
              onAnswer={(code) => void act('/api/live/runs/current/answer', { code })}
              onRequest={(reason) => void act('/api/live/runs/current/release-request', { reason })}
              onApprove={() => void act('/api/live/runs/current/release-approve')}
            />
          ) : null}
        </section>
      ) : null}
    </MainScreen>
  );
}

/** The release stages after which nothing is left for the visitor to do. */
const RELEASE_ENDED: ReadonlySet<string> = new Set(['DONE', 'NO_MAILBOX', 'ABANDONED', 'EXPIRED', 'FAILED']);

/** The reason a real user files the release with: the approval the case records, else the work in plain words. */
function releaseReason(
  t: ReturnType<typeof useTranslation>['t'],
  language: string,
  labCase: LabCase | null,
): string {
  const approval = labCase?.facts.find((fact) => fact.kind === 'APPROVAL') ?? null;
  if (!approval) {
    return t('main.release.reasonPlain');
  }
  return t('show.release.reasonDefault', {
    project: labCase?.requests[0]?.project ?? '-',
    purpose: t(`main.purpose.${approval.purpose ?? 'OTHER'}`),
    approver: approval.approver ?? '-',
    max: approval.maxItems === null ? '-' : count(approval.maxItems, language),
  });
}

/** "같은 상황 측정 5회 · 판단 5건 모두 차단" from the measurement's count of Contexa's judgments of the case. */
function repeatLine(
  t: ReturnType<typeof useTranslation>['t'],
  runs: number,
  actions: Readonly<Record<string, number>>,
): string {
  const label = repeatLabel(actions);
  return t(label.key, {
    runs,
    n: label.n,
    verdict: label.action ? t(verdictChip({ finalAction: label.action, unresolved: false }).key) : '',
    list: Object.entries(actions)
      .filter(([, n]) => n > 0)
      .map(([action, n]) => `${t(verdictChip({ finalAction: action, unresolved: false }).key)} ${n}`)
      .join(' · '),
  });
}

/** The four steps of the extra check (설계서 4-2 추가 인증): asked, code received, code checked, request sent again. */
function recoverySteps(
  stage: string,
): readonly { readonly id: string; readonly state: 'done' | 'now' | 'next' }[] {
  const order = ['asked', 'code', 'check', 'retry'] as const;
  const reached = stage === 'DONE' ? 4 : stage === 'VERIFYING' ? 3 : stage === 'CODE_SHOWN' ? 2 : 1;
  return order.map((id, index) => ({
    id,
    state: index + 1 < reached || stage === 'DONE' ? 'done' : index + 1 === reached ? 'now' : 'next',
  }));
}
