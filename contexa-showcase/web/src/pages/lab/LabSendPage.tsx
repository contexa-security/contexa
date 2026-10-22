import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { postJson } from '../../api/http';
import {
  startLabRun,
  useLabOptions,
  useRecentLabRuns,
  type LabCase,
  type LabPrediction,
} from '../../api/lab';
import { useLiveAnalysis, useLiveRun } from '../../api/queries';
import type { LiveRunView } from '../../api/types';
import { Icon, type IconName } from '../../components/Icon';
import { SourceLine } from '../../components/journey/FrameParts';
import { NextLink } from '../../components/journey/StepParts';
import { LiveChallenge } from '../../components/LiveChallenge';
import { useRecordPath } from '../../components/replay/replayLine';
import { StateScreen } from '../../components/StateScreen';
import { CONTROL_ORDER } from '../../domain/verdict';
import { useLiveSend } from '../../hooks/useLiveSend';
import { ACTIVE, CHECK_ENDED } from '../try/steps/liveRun';
import { Bar } from '../try/steps/LiveRunBar';
import { LabScreen } from './LabScreen';
import {
  CONDITION_KEYS,
  LAB_BAR_WORDS,
  conditionText,
  labQuery,
  readChanges,
  situationName,
} from './labPlace';
import styles from './LabScreens.module.css';

/** The three calls a visitor can make before sending, each with its mark. */
const CALLS: readonly { readonly call: LabPrediction['call']; readonly icon: IconName }[] = [
  { call: 'ATTACK', icon: 'lock' },
  { call: 'NORMAL', icon: 'check' },
  { call: 'UNSURE', icon: 'dash' },
];

/**
 * Predicting and sending (화면재편 R7, T3 then T4): one question, three calls (an attack, legitimate work, not sure) and
 * Send, off until one is picked; the call is stored with the run. Sending goes through the same gate as every live run
 * (the human check, the requests left today). Once sent, the same address keeps the run, so a reload shows it again.
 */
export default function LabSendPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params, setParams] = useSearchParams();
  const options = useLabOptions().data ?? null;
  const caseKey = params.get('case');
  const labCase = options?.cases.find((candidate) => candidate.key === caseKey) ?? null;
  const recordPath = useRecordPath(caseKey ?? '');
  const changes = readChanges(params);
  const changed = Object.keys(changes).length > 0;
  const sent = params.get('sent');
  const [call, setCall] = useState<LabPrediction['call'] | null>(null);
  const { send, sending, ready, refusal, waiting, turnstileContainer, turnstileRequired } = useLiveSend(
    caseKey ?? '',
    (run) => {
      const next = new URLSearchParams(params);
      next.set('sent', run.liveRunId);
      setParams(next, { replace: true });
    },
    {
      post: async (token) => {
        const answer = await startLabRun(
          caseKey ?? '',
          changed ? changes : null,
          { call: call ?? 'UNSURE', approaches: {} },
          token,
        );
        const run = answer.body?.run ?? null;
        const reason = answer.body?.reason;
        // A refusal carries only its reason, which is all the gate reads of it.
        const body = run
          ? { ...run, ...(reason ? { reason } : {}) }
          : reason
            ? ({ reason } as LiveRunView & { readonly reason: string })
            : null;
        return { status: answer.status, body };
      },
      matches: () => true,
    },
  );

  if (!options) {
    return <StateScreen kind="loading" />;
  }
  if (!labCase) {
    return (
      <LabScreen
        step="send"
        type="T3"
        title={t('lab.r7.send.title')}
        purpose={t('lab.r7.change.noCase')}
        back={{ to: '/lab/case', label: t('frame.back') }}
        main={<NextLink to="/lab/case" label={t('lab.r7.toCase')} />}
      >
        {null}
      </LabScreen>
    );
  }
  const query = labQuery(labCase.key, changes);
  if (sent) {
    return <LabRun labCase={labCase} liveRunId={sent} query={query} />;
  }
  // L-23: what is about to be sent, so the call is about a known request: the situation and its change, if any.
  const changedKeys = CONDITION_KEYS.filter((key) => changes[key] !== undefined);
  const change =
    changedKeys.length > 0
      ? t('lab.r7.before.changed', {
          list: changedKeys
            .map((key) =>
              t('lab.r7.before.change', {
                name: t(`lab.field.${key}`),
                from: conditionText(t, key, labCase.conditions[key], options, language),
                to: conditionText(t, key, changes[key], options, language),
              }),
            )
            .join(' · '),
        })
      : t('lab.r7.send.asDesigned');
  return (
    <LabScreen
      step="send"
      type="T3"
      title={t('lab.r7.send.title')}
      purpose={t('lab.r7.send.guide')}
      back={{ to: `/lab/before?${query}`, label: t('frame.back') }}
      main={
        <>
          {/* L-23: the off button says what turns it on. */}
          {call === null ? <span className={styles.offNote}>{t('lab.r7.send.pickFirst')}</span> : null}
          <button
            type="button"
            className={styles.send}
            data-main
            disabled={!ready || call === null}
            onClick={() => void send()}
          >
            {t(sending ? 'lab.r7.send.sending' : 'lab.r7.send.send')}
            <Icon name="arrowRight" />
          </button>
        </>
      }
    >
      <p className={styles.line}>
        <span className={styles.label}>{t('lab.r7.send.what')}</span>
        <span className={styles.strong}>{situationName(t, labCase.key, labCase.title, language)}</span>
        {' · '}
        {change}
      </p>
      {/* The calls are counted apart from the screen's limits (RC-1), like every screen's choice cards. */}
      <fieldset className={styles.choices} data-count="exempt" data-block>
        <legend className="visually-hidden">{t('lab.r7.send.title')}</legend>
        {CALLS.map(({ call: value, icon }) => (
          <label key={value} className={styles.choice} data-selected={call === value || undefined}>
            <input
              type="radio"
              name="call"
              className="visually-hidden"
              checked={call === value}
              onChange={() => setCall(value)}
            />
            <Icon name={icon} className={styles.choiceIcon} />
            <span className={styles.choiceName}>{t(`lab.r7.send.call.${value}`)}</span>
            <span className={styles.choiceHint}>{t(`lab.r7.send.hint.${value}`)}</span>
          </label>
        ))}
      </fieldset>
      {turnstileRequired ? <div ref={turnstileContainer} /> : null}
      {waiting ? <p className={styles.line}>{t('p1.predict.waitEarlier')}</p> : null}
      {refusal ? (
        <StateScreen
          kind={refusal === 'dailyLimit' ? 'dailyLimit' : refusal === 'paused' ? 'paused' : 'outage'}
          recordTo={recordPath}
          {...(refusal === 'error' || refusal === 'turnstile' ? { onRetry: () => void send() } : {})}
        />
      ) : null}
    </LabScreen>
  );
}

interface LabRunProps {
  readonly labCase: LabCase;
  readonly liveRunId: string;
  readonly query: string;
}

/**
 * The sent run (T4), drawn as the tries draw theirs: the time line of the five answers to the latest request sent,
 * "send the next request" while a case of several requests waits, the identity check when Contexa asks for one, and
 * "see the result" once the run has ended. What the engine received stays in the decision details.
 */
function LabRun({ labCase, liveRunId, query }: LabRunProps) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const live = useLiveRun(true);
  const view: LiveRunView | null = live.data?.liveRunId === liveRunId ? live.data : null;
  const analysing = view !== null && view.status !== 'QUEUED' && view.status !== 'STARTING';
  const analysis = useLiveAnalysis(view?.liveRunId ?? null, 1, analysing);
  const decision = analysis.data?.decision ?? null;
  const recent = useRecentLabRuns().data ?? [];
  const steps = labCase.requests.length;
  const finished = view !== null && !ACTIVE.has(view.status) && view.runId !== null;
  // The visitor's previous lab run of the same case, the one the result compares this run with.
  const previous =
    recent.find((entry) => entry.caseKey === labCase.key && entry.runId !== view?.runId)?.runId ?? null;

  async function act(path: string, body: Record<string, string> = {}) {
    const response = await postJson<LiveRunView>(path, body);
    if (response.body && response.status < 300) {
      queryClient.setQueryData(['live-run'], response.body);
    }
  }

  if (live.isPending) {
    return <StateScreen kind="loading" />;
  }
  const resultTo =
    finished && view?.runId
      ? `/lab/result?run=${encodeURIComponent(view.runId)}${previous ? `&against=${encodeURIComponent(previous)}` : ''}`
      : null;
  // The latest request sent: its five answers are the line the visitor watches.
  const stepNo = view ? Math.max(1, ...view.steps.map((step) => step.stepNo)) : 1;
  const layers = view?.steps.find((step) => step.stepNo === stepNo)?.layers ?? {};
  const streams = view?.steps.find((step) => step.stepNo === stepNo)?.streams ?? {};
  const axis = Math.max(
    ...CONTROL_ORDER.map((control) => layers[control]?.elapsedMs ?? streams[control]?.atMs ?? 0),
    1,
  );
  const remaining = analysing && !decision ? (analysis.data?.decisionWait?.remainingSeconds ?? null) : null;

  // V-04: the request is named only in a run of more than one request sent, or one waiting for the next.
  const named = view !== null && (view.steps.length > 1 || view.status === 'AWAITING');
  // L-26: while the request goes out on its own, nothing offers to leave it; a wait for the visitor (the next request,
  // the identity check, the queue) keeps the way back.
  const going = view !== null && (view.status === 'STARTING' || view.status === 'RUNNING');

  return (
    <LabScreen
      step="send"
      type="T4"
      // V-04: an ended run is titled as ended, not as still sending.
      title={t(finished ? 'lab.r7.run.titleDone' : 'lab.r7.run.title')}
      purpose={view ? t(finished ? 'lab.r7.run.guideDone' : 'lab.r7.run.guide') : t('lab.r7.run.ended')}
      sourceLine={finished && view?.runId ? <SourceLine kind="run" runId={view.runId} /> : null}
      back={going ? null : { to: `/lab/change?${query}`, label: t('frame.back') }}
      main={resultTo ? <NextLink to={resultTo} label={t('lab.r7.run.next')} /> : null}
    >
      {view?.status === 'QUEUED' ? (
        <StateScreen
          kind="queued"
          queuePosition={view.queuePosition}
          remainingSeconds={view.queueWaitSeconds}
        />
      ) : null}
      {view?.status === 'STARTING' ? <p className={styles.line}>{t('e1.run.preparing')}</p> : null}
      {view && view.status !== 'QUEUED' && view.status !== 'STARTING' ? (
        <section className={styles.request} aria-label={t('lab.r7.run.title')}>
          {/* One block for the gap check: the request's name and its five answers belong together. */}
          <div className={styles.requestLine} data-block>
            {named ? (
              <h2 className={styles.requestTitle}>{t('lab.r7.run.request', { n: stepNo, total: steps })}</h2>
            ) : null}
            <ul className={styles.bars}>
              {CONTROL_ORDER.map((control) => (
                <Bar
                  key={control}
                  control={control}
                  layer={layers[control] ?? null}
                  stream={streams[control] ?? null}
                  axis={axis}
                  held={false}
                  words={LAB_BAR_WORDS}
                  verdict={stepNo === 1 && control === 'D' ? (decision?.finalAction ?? null) : null}
                  decidingKey="p1.run.deciding"
                  deciding={stepNo === 1 && control === 'D' && decision === null && !finished}
                  waitingLabel={
                    stepNo === 1 && control === 'D' && remaining !== null
                      ? t('p1.run.waitingFor', { seconds: remaining })
                      : undefined
                  }
                />
              ))}
            </ul>
          </div>
          {view.status === 'AWAITING' ? (
            <button
              type="button"
              className={styles.sendNext}
              onClick={() => void act('/api/live/runs/current/next')}
            >
              {t('p1.run.sendNext')}
            </button>
          ) : null}
        </section>
      ) : null}
      {view?.challenge && finished && CHECK_ENDED.has(view.challenge.stage) ? (
        <p className={styles.line}>
          {t('labSend.check', {
            result: t(`e1.after.reason.${view.challenge.stage}`, {
              defaultValue: t('e1.after.reason.other'),
            }),
          })}
        </p>
      ) : view?.challenge ? (
        <LiveChallenge
          challenge={view.challenge}
          onRequestCode={() => void act('/api/live/runs/current/code')}
          onAnswer={(code) => void act('/api/live/runs/current/answer', { code })}
          onCancel={() => void act('/api/live/runs/current/cancel')}
          onRestart={() => void act('/api/live/runs/current/abandon')}
        />
      ) : null}
    </LabScreen>
  );
}
