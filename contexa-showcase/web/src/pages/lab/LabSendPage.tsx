import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useAnatomies } from '../../api/anatomy';
import { postJson } from '../../api/http';
import {
  startLabRun,
  useLabOptions,
  useRecentLabRuns,
  useRunStepResults,
  type LabCase,
  type LabPrediction,
} from '../../api/lab';
import { useLiveAnalysis, useLiveConfig, useLiveRun } from '../../api/queries';
import type { LiveRunView } from '../../api/types';
import { CumulativeMeter } from '../../components/inside/CumulativeMeter';
import { InsidePanel } from '../../components/inside/InsidePanel';
import { meterRows } from '../../components/inside/meterRows';
import { NextLink } from '../../components/journey/StepParts';
import { LiveChallenge } from '../../components/LiveChallenge';
import { Icon } from '../../components/Icon';
import { useRecordPath } from '../../components/replay/replayLine';
import { StateScreen } from '../../components/StateScreen';
import { CONTROL_ORDER } from '../../domain/verdict';
import { useLiveSend } from '../../hooks/useLiveSend';
import { seconds } from '../../journey/format';
import experience from '../try/Experience.module.css';
import { ACTIVE, CHECK_ENDED, panelCells, requestName } from '../try/steps/liveRun';
import { Bar } from '../try/steps/LiveRunBar';
import { LabScreen } from './LabScreen';
import { labQuery, readChanges } from './labPlace';
import styles from './LabPages.module.css';

const CALLS = ['ATTACK', 'NORMAL', 'UNSURE'] as const;
const GUESSES = ['BLOCK', 'PASS'] as const;

/**
 * L2-3, predicting and sending (7.6): the visitor's call before sending (attack, legitimate work or unsure, and a guess
 * per approach folded away), the human check and the runs left today, then the real run on the same screen with the
 * time bars and the inside panel, the meter pinned for a case of several requests. The run's address keeps the sent
 * run, so a reload shows it again.
 */
export default function LabSendPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const options = useLabOptions().data ?? null;
  const config = useLiveConfig().data ?? null;
  const caseKey = params.get('case');
  const labCase = options?.cases.find((candidate) => candidate.key === caseKey) ?? null;
  const recordPath = useRecordPath(caseKey ?? '');
  const changes = readChanges(params);
  const changed = Object.keys(changes).length > 0;
  const sent = params.get('sent');
  const [call, setCall] = useState<LabPrediction['call'] | null>(null);
  const [approaches, setApproaches] = useState<LabPrediction['approaches']>({});
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
          { call: call ?? 'UNSURE', approaches },
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
  const query = labCase ? labQuery(labCase.key, changes) : '';

  if (!options) {
    return <StateScreen kind="loading" />;
  }
  if (!labCase) {
    return (
      <LabScreen
        step="send"
        title={t('labSend.title')}
        purpose={t('labChange.noCase')}
        back={{ to: '/lab/case', label: t('labChange.back') }}
      >
        {null}
      </LabScreen>
    );
  }
  if (sent) {
    return <LabRun labCase={labCase} liveRunId={sent} changes={changes} query={query} />;
  }
  return (
    <LabScreen
      step="send"
      title={t('labSend.title')}
      purpose={t('labSend.purpose')}
      back={{ to: `/lab/before?${query}`, label: t('labSend.back') }}
      main={
        <div className={experience.sendBlock}>
          <button
            type="button"
            className={experience.send}
            data-main
            disabled={!ready || call === null}
            onClick={() => void send()}
          >
            {sending ? t('e1.predict.sending') : t('labSend.send')}
            <Icon name="arrowRight" />
          </button>
          <span className={experience.sendNote}>
            {call === null
              ? t('labSend.pickFirst')
              : config
                ? t('exp.console.note', { remaining: config.remainingToday })
                : null}
          </span>
        </div>
      }
    >
      <fieldset className={styles.panel}>
        <legend className={styles.panelTitle}>{t('labSend.call')}</legend>
        <div className={styles.filters}>
          {CALLS.map((value) => (
            <label key={value} className={styles.choice} data-chosen={call === value || undefined}>
              <input
                type="radio"
                name="call"
                value={value}
                checked={call === value}
                onChange={() => setCall(value)}
              />
              {t(`labSend.calls.${value}`)}
            </label>
          ))}
        </div>
        <details className={styles.advanced}>
          <summary>{t('labSend.approaches')}</summary>
          <div className={styles.advancedInputs}>
            {CONTROL_ORDER.map((control) => (
              <label key={control} className={styles.advancedInput}>
                <span>{t(`control.${control}.name`)}</span>
                <select
                  className={styles.select}
                  value={approaches[control] ?? ''}
                  onChange={(event) => {
                    const value = event.target.value as (typeof GUESSES)[number] | '';
                    setApproaches((current) => {
                      const others = Object.fromEntries(
                        Object.entries(current).filter(([name]) => name !== control),
                      ) as LabPrediction['approaches'];
                      return value === '' ? others : { ...others, [control]: value };
                    });
                  }}
                >
                  <option value="">{t('labSend.guess.none')}</option>
                  {GUESSES.map((guess) => (
                    <option key={guess} value={guess}>
                      {t(`labSend.guess.${guess}`)}
                    </option>
                  ))}
                </select>
              </label>
            ))}
          </div>
        </details>
      </fieldset>
      {turnstileRequired ? <div ref={turnstileContainer} /> : null}
      {waiting ? <p className={styles.note}>{t('live.sendAfterEarlier')}</p> : null}
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
  readonly changes: Record<string, unknown>;
  readonly query: string;
}

/** The sent run, drawn as the tries draw theirs: the time bars, the inside panel, the check and the next request. */
function LabRun({ labCase, liveRunId, changes, query }: LabRunProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const queryClient = useQueryClient();
  const live = useLiveRun(true);
  const view: LiveRunView | null = live.data?.liveRunId === liveRunId ? live.data : null;
  const analysing = view !== null && view.status !== 'QUEUED' && view.status !== 'STARTING';
  const analysis = useLiveAnalysis(view?.liveRunId ?? null, 1, analysing);
  const decision = analysis.data?.decision ?? null;
  const recent = useRecentLabRuns().data ?? [];
  const steps = labCase.requests.length;
  const finished = view !== null && !ACTIVE.has(view.status) && view.runId !== null;
  const anatomies = useAnatomies(finished && steps > 1 ? view.runId : null, steps).map((entry) => entry.data);
  const results = useRunStepResults(finished && steps > 1 ? view.runId : null, steps);
  // The case as sent: a changed count is what the first request asked for.
  const sentCase: LabCase =
    changes['items'] !== undefined
      ? {
          ...labCase,
          requests: labCase.requests.map((request, index) =>
            index === 0 ? { ...request, items: changes['items'] as number } : request,
          ),
        }
      : labCase;
  // The visitor's previous lab run of the same case, the one this run is compared with.
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
  return (
    <LabScreen
      step="send"
      title={t('labSend.runTitle')}
      purpose={t('labSend.runPurpose')}
      back={{ to: `/lab/change?${query}`, label: t('labSend.toChange') }}
      main={resultTo ? <NextLink to={resultTo} label={t('labSend.toResult')} /> : null}
    >
      {view === null ? <p className={styles.note}>{t('labSend.ended')}</p> : null}
      {view && steps > 1 && finished ? (
        <CumulativeMeter caption={t('labSend.meter')} rows={meterRows(anatomies, results)} />
      ) : null}
      {view ? (
        <div className={experience.runGrid}>
          <div className={experience.runMain}>
            <ul className={experience.legend} aria-label={t('e1.run.legend.label')}>
              <li>
                <span className={experience.swatch} data-outcome="DELIVERED" aria-hidden="true" />
                {t('e1.run.legend.out')}
              </li>
              <li>
                <span className={experience.swatch} data-outcome="STOPPED" aria-hidden="true" />
                {t('e1.run.legend.denied')}
              </li>
            </ul>
            {view.status === 'QUEUED' ? (
              <StateScreen
                kind="queued"
                queuePosition={view.queuePosition}
                remainingSeconds={view.queueWaitSeconds}
              />
            ) : null}
            {labCase.requests.map((_, index) => {
              const stepNo = index + 1;
              const stepLayers = view.steps.find((step) => step.stepNo === stepNo)?.layers ?? {};
              const sentStep = stepNo === 1 || view.steps.some((step) => step.stepNo === stepNo);
              const axis = Math.max(
                ...CONTROL_ORDER.map((control) => stepLayers[control]?.elapsedMs ?? 0),
                1,
              );
              const what = requestName(t, language, sentCase, stepNo);
              return (
                <section key={stepNo} className={experience.runStep} aria-label={what}>
                  {steps > 1 ? (
                    <h2 className={experience.sectionTitle}>
                      {t(stepNo === 1 ? 'e1.run.request.first' : 'e1.run.request.next', { what })}
                    </h2>
                  ) : null}
                  {view.status === 'AWAITING' && view.awaitingStep === stepNo ? (
                    <button
                      type="button"
                      className={experience.primary}
                      onClick={() => void act('/api/live/runs/current/next')}
                    >
                      {t('e1.run.sendNext', { what })}
                    </button>
                  ) : null}
                  {sentStep ? (
                    <ul className={experience.bars}>
                      {CONTROL_ORDER.map((control) => (
                        <Bar
                          key={control}
                          control={control}
                          layer={stepLayers[control] ?? null}
                          axis={axis}
                          held={false}
                          verdict={stepNo === 1 && control === 'D' ? (decision?.finalAction ?? null) : null}
                        />
                      ))}
                    </ul>
                  ) : null}
                  {CONTROL_ORDER.every((control) => stepLayers[control] !== undefined) ? (
                    <p className={experience.axis}>
                      <span aria-hidden="true" />
                      <span className={experience.axisScale}>
                        <span>{t('e1.run.axis', { seconds: '0' })}</span>
                        <span>{t('e1.run.axis', { seconds: seconds(axis / 2) })}</span>
                        <span>{t('e1.run.axis', { seconds: seconds(axis) })}</span>
                      </span>
                    </p>
                  ) : null}
                </section>
              );
            })}
            {analysing && !decision && !finished ? (
              <StateScreen
                kind="waiting"
                remainingSeconds={analysis.data?.decisionWait?.remainingSeconds ?? null}
              />
            ) : null}
            {view.challenge && finished && CHECK_ENDED.has(view.challenge.stage) ? (
              <p className={styles.note}>
                {t('labSend.check', {
                  result: t(`e1.after.reason.${view.challenge.stage}`, {
                    defaultValue: t('e1.after.reason.other'),
                  }),
                })}
              </p>
            ) : view.challenge ? (
              <LiveChallenge
                challenge={view.challenge}
                onRequestCode={() => void act('/api/live/runs/current/code')}
                onAnswer={(code) => void act('/api/live/runs/current/answer', { code })}
                onCancel={() => void act('/api/live/runs/current/cancel')}
                onRestart={() => void act('/api/live/runs/current/abandon')}
              />
            ) : null}
          </div>
          <InsidePanel
            cells={panelCells(
              t,
              language,
              sentCase,
              view,
              analysis.data?.stages ?? null,
              decision,
              analysis.data?.decisionWait?.waitedMs ?? null,
            )}
          />
        </div>
      ) : null}
    </LabScreen>
  );
}
