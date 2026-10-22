import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { postJson } from '../../../api/http';
import type { LabCase } from '../../../api/lab';
import type { LiveRunView } from '../../../api/types';
import { SourceLine } from '../../../components/journey/FrameParts';
import { ScreenBody } from '../../../components/journey/ScreenBody';
import { NextLink } from '../../../components/journey/StepParts';
import { LiveChallenge } from '../../../components/LiveChallenge';
import { StateScreen } from '../../../components/StateScreen';
import { CONTROL_ORDER } from '../../../domain/verdict';
import type { Difference } from '../../../journey/journey';
import { focusHeading } from '../../../journey/focus';
import { useJourneyPlace } from '../../../journey/useJourneyPlace';
import { stepPath, type Mode, type Role, type StepFlow } from '../experience';
import { useRunStepResults } from '../../../api/lab';
import { priorOf } from '../../../components/inside/meterRows';
import { Bar } from './LiveRunBar';
import styles from './RunStep.module.css';
import { useTryAnalysis, useTryRun } from './tryRun';

interface RunStepProps {
  readonly role: Role;
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/**
 * Screens 1-3 and 2-2, watching the run (T4): the same request at five places at once, each answer drawn on one time
 * line by its real response time as it arrives, and "see the result" once all five have answered. While it goes the
 * screen shows the run's own state (in line, preparing, waiting for the judgment). The person with a stolen account
 * who meets an identity check asks for the code, which goes to the real employee's mailbox; the real employee answers
 * the check here.
 */
export function RunStep({ role, mode, labCase, see, flow }: RunStepProps) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const number = useJourneyPlace().screen?.number ?? (role === 'attacker' ? '1-3' : '2-2');
  const run = useTryRun(labCase.key, labCase.requests.length);
  const view: LiveRunView | null = run.view;
  const layers = view?.steps.find((step) => step.stepNo === 1)?.layers ?? {};
  const analysing = view !== null && !run.stored && view.status !== 'QUEUED' && view.status !== 'STARTING';
  const analysis = useTryAnalysis(view, run.stored);
  // Later requests' stored answers, read once the run has ended (their Contexa line has no live judgment).
  const laterResults = useRunStepResults(
    view?.status === 'COMPLETED' ? view.runId : null,
    labCase.requests.length,
  );
  const decision = analysis.decision;
  const contexa = layers.D ?? null;
  const allDone = CONTROL_ORDER.every((control) => layers[control] !== undefined);
  const asked = useRef<string | null>(null);
  const title = t(`screen.${number}.title`);
  const toPredict = stepPath(role, 'predict', mode);
  const remaining = analysing && !decision ? (analysis.wait?.remainingSeconds ?? null) : null;

  // Someone with a stolen account asks for the code at once; it goes to the real employee's mailbox (e1-after).
  useEffect(() => {
    if (
      role === 'attacker' &&
      view?.status === 'CHALLENGE' &&
      view.challenge?.stage === 'WAITING' &&
      asked.current !== view.liveRunId
    ) {
      asked.current = view.liveRunId;
      void postJson<LiveRunView>('/api/live/runs/current/code', {}).then((response) => {
        if (response.body && response.status < 300) {
          queryClient.setQueryData(['live-run'], response.body);
        }
      });
    }
  }, [role, view?.status, view?.challenge?.stage, view?.liveRunId, queryClient]);

  useEffect(() => {
    if (contexa) {
      see(1);
    }
    // Seen once Contexa answered; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [contexa !== null]);

  if (run.pending) {
    return <StateScreen kind="loading" />;
  }
  if (view === null) {
    return (
      <ScreenBody
        title={title}
        purpose={t('p1.notSent')}
        back={flow.back}
        main={<NextLink to={toPredict} label={t('p1.toPredict')} />}
      >
        {null}
      </ScreenBody>
    );
  }
  if (view.status === 'FAILED' || view.status === 'EXPIRED') {
    return (
      <ScreenBody
        title={title}
        purpose={t('p1.run.failed')}
        back={flow.back}
        main={<NextLink to={toPredict} label={t('p1.run.retry')} />}
      >
        <StateScreen kind="outage" recordTo="/" />
      </ScreenBody>
    );
  }

  const stepNumbers = labCase.requests.map((_, index) => index + 1);
  const lastLayers = view.steps.find((step) => step.stepNo === labCase.requests.length)?.layers ?? {};
  const finished = CONTROL_ORDER.every((control) => lastLayers[control] !== undefined);
  // A step the visitor sends themselves (visitorSends) may be left unsent until the run closes; it is then done with the
  // requests it has, never waiting for one that will not come.
  const closed = view.status === 'COMPLETED';
  const done = allDone && (finished || closed);

  async function act(path: string, body: Record<string, string> = {}) {
    const response = await postJson<LiveRunView>(path, body);
    if (response.body && response.status < 300) {
      queryClient.setQueryData(['live-run'], response.body);
    }
  }

  return (
    <ScreenBody
      title={title}
      purpose={t(number === '4-1' ? 'screen.1-3.guide' : `screen.${number}.guide`)}
      sourceLine={done && view.runId ? <SourceLine kind="run" runId={view.runId} /> : null}
      back={flow.back}
      main={done ? flow.next : null}
    >
      {view.status === 'QUEUED' ? (
        <StateScreen
          kind="queued"
          queuePosition={view.queuePosition}
          remainingSeconds={view.queueWaitSeconds}
        />
      ) : null}
      {view.status === 'STARTING' ? <p className={styles.note}>{t('e1.run.preparing')}</p> : null}
      {stepNumbers.map((stepNo) => {
        const stepLayers = view.steps.find((step) => step.stepNo === stepNo)?.layers ?? {};
        const stepStreams = view.steps.find((step) => step.stepNo === stepNo)?.streams ?? {};
        const sent = stepNo === 1 || view.steps.some((step) => step.stepNo === stepNo);
        // The time line is as long as the slowest answer, so every bar is drawn to the same scale.
        const axis = Math.max(
          ...CONTROL_ORDER.map(
            (control) => stepLayers[control]?.elapsedMs ?? stepStreams[control]?.atMs ?? 0,
          ),
          1,
        );
        const name = t(stepNo === 1 ? 'p1.run.request.first' : 'p1.run.request.next');
        return (
          <section key={stepNo} className={styles.request} aria-label={name}>
            {stepNumbers.length > 1 ? <h2 className={styles.requestTitle}>{name}</h2> : null}
            {view.status === 'AWAITING' && view.awaitingStep === stepNo ? (
              <button
                type="button"
                className={styles.sendNext}
                onClick={() => {
                  void act('/api/live/runs/current/next');
                  // The button goes once the request is sent; the focus goes to the headline (RC-9).
                  focusHeading();
                }}
              >
                {t('p1.run.sendNext')}
              </button>
            ) : null}
            {sent ? (
              <ul className={styles.bars}>
                {CONTROL_ORDER.map((control) => (
                  <Bar
                    key={control}
                    control={control}
                    layer={stepLayers[control] ?? null}
                    stream={stepStreams[control] ?? null}
                    axis={axis}
                    held={stepNo === 1 && control === 'D' && mode === 'sync'}
                    verdict={
                      control !== 'D'
                        ? null
                        : stepNo === 1
                          ? (decision?.finalAction ?? null)
                          : (laterResults[stepNo - 1]?.layers.find((layer) => layer.control === 'D')
                              ?.verdict ?? null)
                    }
                    prior={stepNo > 1 && control === 'D' && priorOf(laterResults[stepNo - 1])}
                    decidingKey="p1.run.deciding"
                    deciding={stepNo === 1 && control === 'D' && decision === null && !analysis.missing}
                    answerOnly={stepNumbers.length > 1}
                    waitingLabel={
                      stepNo === 1 && control === 'D' && remaining !== null
                        ? t('p1.run.waitingFor', { seconds: remaining })
                        : undefined
                    }
                  />
                ))}
              </ul>
            ) : null}
          </section>
        );
      })}
      {role === 'owner' && view.challenge ? (
        // The real employee who meets the check answers it here: the code is in their own demo inbox (e2-check).
        <LiveChallenge
          challenge={view.challenge}
          onRequestCode={() => void act('/api/live/runs/current/code')}
          onAnswer={(code) => void act('/api/live/runs/current/answer', { code })}
          onCancel={() => void act('/api/live/runs/current/cancel')}
          onRestart={() => void navigate(toPredict)}
        />
      ) : null}
    </ScreenBody>
  );
}
