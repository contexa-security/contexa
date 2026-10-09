import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { postJson } from '../../../api/http';
import type { LabCase } from '../../../api/lab';
import type { LiveRunView } from '../../../api/types';
import { SourceMark } from '../../../components/common/SourceMark';
import { InsidePanel } from '../../../components/inside/InsidePanel';
import { LiveChallenge } from '../../../components/LiveChallenge';
import { JustSaw } from '../../../components/journey/JourneyParts';
import { ActionBar, StepHeader } from '../../../components/journey/StepParts';
import { StateScreen } from '../../../components/StateScreen';
import { CONTROL_ORDER } from '../../../domain/verdict';
import { seconds } from '../../../journey/format';
import type { Difference } from '../../../journey/journey';
import { stepPath, type Mode, type Role, type StepFlow } from '../experience';
import styles from '../Experience.module.css';
import { panelCells, requestName } from './liveRun';
import { Bar } from './LiveRunBar';
import { useStoredCheck, useTryAnalysis, useTryRun } from './tryRun';

interface RunStepProps {
  readonly role: Role;
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/**
 * Try 1-4, the run (e1-run): the same request at five places at once, each answer drawn on a time axis by its real
 * response time as it arrives, with one legend line for what the colors mean, and the inside panel lit by the engine's
 * own analysis events. The person with a stolen account who meets an identity check asks for the code, which goes to
 * the real employee's mailbox.
 */
export function RunStep({ role, mode, labCase, see, flow }: RunStepProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const run = useTryRun(labCase.key, labCase.requests.length);
  const view: LiveRunView | null = run.view;
  const layers = view?.steps.find((step) => step.stepNo === 1)?.layers ?? {};
  const analysing = view !== null && !run.stored && view.status !== 'QUEUED' && view.status !== 'STARTING';
  const analysis = useTryAnalysis(view, run.stored);
  const decision = analysis.decision;
  const storedCheck = useStoredCheck(run.runId, run.stored);
  const contexa = layers.D ?? null;
  const allDone = CONTROL_ORDER.every((control) => layers[control] !== undefined);
  const asked = useRef<string | null>(null);

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
      <>
        <StepHeader title={t('e1.run.title')} purpose={t('e1.run.notSent')} />
        <ActionBar back={{ to: stepPath(role, 'predict', mode), label: t('e1.run.toPredict') }} />
      </>
    );
  }
  if (view.status === 'FAILED' || view.status === 'EXPIRED') {
    return (
      <>
        <StateScreen kind="outage" recordTo="/" />
        <ActionBar back={{ to: stepPath(role, 'predict', mode), label: t('e1.run.retry') }} />
      </>
    );
  }

  const cells = panelCells(
    t,
    language,
    labCase,
    view,
    analysis.stages,
    decision,
    analysis.wait?.waitedMs ?? null,
    storedCheck,
  );
  const stepNumbers = labCase.requests.map((_, index) => index + 1);
  const lastLayers = view.steps.find((step) => step.stepNo === labCase.requests.length)?.layers ?? {};
  const finished = CONTROL_ORDER.every((control) => lastLayers[control] !== undefined);
  const what = (stepNo: number) => requestName(t, language, labCase, stepNo);

  async function sendNext() {
    await act('/api/live/runs/current/next');
  }

  async function act(path: string, body: Record<string, string> = {}) {
    const response = await postJson<LiveRunView>(path, body);
    if (response.body && response.status < 300) {
      queryClient.setQueryData(['live-run'], response.body);
    }
  }

  return (
    <div className={styles.runGrid}>
      <div className={styles.runMain}>
        <StepHeader
          title={t('e1.run.title')}
          purpose={t('e1.purpose.run')}
          source={view.runId ? <SourceMark kind="ENGINE" runId={view.runId} step={1} /> : null}
        />
        <ul className={styles.legend} aria-label={t('e1.run.legend.label')}>
          <li>
            <span className={styles.swatch} data-outcome="DELIVERED" aria-hidden="true" />
            {t('e1.run.legend.out')}
          </li>
          <li>
            <span className={styles.swatch} data-outcome="STOPPED" aria-hidden="true" />
            {t('e1.run.legend.denied')}
          </li>
          {mode === 'sync' ? (
            <li>
              <span className={styles.swatch} data-held="true" aria-hidden="true" />
              {t('e1.run.legend.held')}
            </li>
          ) : null}
        </ul>
        {view.status === 'QUEUED' ? (
          <StateScreen
            kind="queued"
            queuePosition={view.queuePosition}
            remainingSeconds={view.queueWaitSeconds}
          />
        ) : null}
        {view.status === 'STARTING' ? <p className={styles.lead}>{t('e1.run.preparing')}</p> : null}
        {stepNumbers.map((stepNo) => {
          const stepLayers = view.steps.find((step) => step.stepNo === stepNo)?.layers ?? {};
          const sent = stepNo === 1 || view.steps.some((step) => step.stepNo === stepNo);
          const axis = Math.max(...CONTROL_ORDER.map((control) => stepLayers[control]?.elapsedMs ?? 0), 1);
          const answered = CONTROL_ORDER.every((control) => stepLayers[control] !== undefined);
          return (
            <section key={stepNo} className={styles.runStep} aria-label={what(stepNo)}>
              {stepNumbers.length > 1 ? (
                <h2 className={styles.sectionTitle}>
                  {t(stepNo === 1 ? 'e1.run.request.first' : 'e1.run.request.next', { what: what(stepNo) })}
                </h2>
              ) : null}
              {view.status === 'AWAITING' && view.awaitingStep === stepNo ? (
                <button type="button" className={styles.primary} onClick={() => void sendNext()}>
                  {t('e1.run.sendNext', { what: what(stepNo) })}
                </button>
              ) : null}
              {sent ? (
                <ul className={styles.bars}>
                  {CONTROL_ORDER.map((control) => (
                    <Bar
                      key={control}
                      control={control}
                      layer={stepLayers[control] ?? null}
                      axis={axis}
                      held={stepNo === 1 && control === 'D' && mode === 'sync'}
                      verdict={stepNo === 1 && control === 'D' ? (decision?.finalAction ?? null) : null}
                    />
                  ))}
                </ul>
              ) : null}
              {answered ? (
                <p className={styles.axis}>
                  <span aria-hidden="true" />
                  <span className={styles.axisScale}>
                    <span>{t('e1.run.axis', { seconds: '0' })}</span>
                    <span>{t('e1.run.axis', { seconds: seconds(axis / 2) })}</span>
                    <span>{t('e1.run.axis', { seconds: seconds(axis) })}</span>
                  </span>
                </p>
              ) : null}
            </section>
          );
        })}
        {analysing && !contexa && !decision ? (
          <StateScreen
            kind="waiting"
            remainingSeconds={analysis.wait?.remainingSeconds ?? null}
          />
        ) : null}
        {role === 'owner' && view.challenge ? (
          // The real employee who meets the check answers it here: the code is in their own demo inbox (e2-check).
          <LiveChallenge
            challenge={view.challenge}
            onRequestCode={() => void act('/api/live/runs/current/code')}
            onAnswer={(code) => void act('/api/live/runs/current/answer', { code })}
            onCancel={() => void act('/api/live/runs/current/cancel')}
            onRestart={() => void navigate(stepPath(role, 'predict', mode))}
          />
        ) : null}
        {contexa && role === 'attacker' ? <JustSaw difference={1} sentence="e1Run" /> : null}
        <ActionBar back={flow.back} main={finished && allDone ? flow.next : null} teaser={flow.teaser} />
      </div>
      <InsidePanel cells={cells} />
    </div>
  );
}
