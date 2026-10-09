import { useEffect, useState } from 'react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { postJson } from '../../api/http';
import {
  startLabRun,
  useLabOptions,
  useRecentLabRuns,
  useRunStepResults,
  useStepResult,
  type LabCase,
  type LabConditions,
  type LabOptions,
  type LabPrediction,
  type RecentLabRun,
} from '../../api/lab';
import { useAnatomy, type DecisionAnatomyView } from '../../api/anatomy';
import {
  useBaseline,
  useLiveAnalysis,
  useLiveConfig,
  useLiveRun,
  useRunScore,
  useVisitor,
} from '../../api/queries';
import type { AnalysisStage, LiveRunView, RunScore, StepResult } from '../../api/types';
import { AppHeader } from '../../components/AppHeader';
import { ApproachResults } from '../../components/approaches/ApproachResults';
import { AssessPanel } from '../../components/assessment/AssessPanel';
import { LiveChallenge } from '../../components/LiveChallenge';
import { StateScreen } from '../../components/StateScreen';
import { refusalOf, type GateRefusal } from '../../domain/live';
import { CONTROL_ORDER, OUTCOME_KEYS, type ControlId } from '../../domain/verdict';
import { useTurnstile } from '../../hooks/useTurnstile';
import styles from './LabPage.module.css';

/*
 * The lab (docs/showcase/데모-재설계.md 5A.1, the W3 draft as approved): the visitor composes a request (1), calls it
 * before sending (2), watches it run and reads the result (3), compares it with their previous run (4) and assesses
 * Contexa's decision (5). The choices come from /api/lab/options, the run from the visitor's own live run, the results
 * from the stored step results and score; nothing here computes a judgement of its own.
 */
const FIELDS: readonly (keyof LabConditions)[] = [
  'employee',
  'timeSlot',
  'place',
  'device',
  'operation',
  'target',
  'items',
  'approval',
  'ticket',
  'claim',
  'onCall',
];

/** The minimum wait between the steps of a paced case: the engine's verdict applies from the next request. */
const ALLOW_WINDOW_SECONDS = 15;

const ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED']);
const ANALYSIS_SHOWN = new Set([
  'CONTEXT_COLLECTED',
  'LAYER1_START',
  'LAYER1_COMPLETE',
  'LAYER2_START',
  'LAYER2_COMPLETE',
  'DECISION_APPLIED',
  'ANALYSIS_ERROR',
]);

function valueText(field: keyof LabConditions, value: unknown, options: LabOptions, t: TFunction): string {
  if (value === null || value === undefined) {
    return t('lab.value.none');
  }
  if (field === 'employee') {
    return options.employees.find((employee) => employee.key === value)?.displayName ?? String(value);
  }
  if (field === 'timeSlot') {
    const slot = options.timeSlots.find((candidate) => candidate.slot === value);
    return t(`lab.slot.${String(value)}`, { time: slot?.representativeTime ?? '' });
  }
  if (typeof value === 'boolean') {
    return t(value ? 'lab.value.yes' : 'lab.value.no');
  }
  if (field === 'items') {
    return t('lab.value.items', { n: Number(value) });
  }
  return t(`lab.${field}.${String(value)}`);
}

export default function LabPage() {
  const { t } = useTranslation();
  // The visitor cookie (and the CSRF cookie) come first: the visitor's own runs and sending need them.
  const visitor = useVisitor();
  const options = useLabOptions();
  return (
    <>
      <AppHeader />
      <main id="main" className={styles.page}>
        <header className={styles.head}>
          <h1 className={styles.title}>{t('lab.title')}</h1>
          <ol className={styles.activities} aria-label={t('lab.activitiesLabel')}>
            {(['compose', 'judge', 'watch', 'compare', 'assess'] as const).map((activity, index) => (
              <li key={activity}>
                <span className={styles.activityNumber}>{index + 1}</span>
                {t(`lab.activity.${activity}`)}
              </li>
            ))}
          </ol>
        </header>
        {options.data && visitor.isSuccess ? (
          <Lab options={options.data} />
        ) : options.isError ? (
          <StateScreen kind="liveClosed" />
        ) : visitor.isError ? (
          <StateScreen kind="error" onRetry={() => void visitor.refetch()} />
        ) : (
          <p>{t('anatomy.loading')}</p>
        )}
      </main>
    </>
  );
}

interface Attempt {
  readonly sending: boolean;
  readonly refusal: GateRefusal | null;
  readonly reason: string | null;
}

function Lab({ options }: { readonly options: LabOptions }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const recent = useRecentLabRuns().data ?? [];
  const latest = recent[0] ?? null;
  const previous = recent[1] ?? null;
  const initialCase =
    options.cases.find((candidate) => candidate.key === latest?.caseKey) ?? options.cases[0];
  const [caseKey, setCaseKey] = useState(initialCase?.key ?? '');
  const designed = options.cases.find((candidate) => candidate.key === caseKey) ?? initialCase;
  const [conditions, setConditions] = useState<LabConditions | null>(
    latest && designed && latest.caseKey === designed.key
      ? { ...designed.conditions, ...latest.conditions }
      : (designed?.conditions ?? null),
  );
  const [call, setCall] = useState<LabPrediction['call'] | null>(null);
  const [approaches, setApproaches] = useState<Partial<Record<ControlId, 'BLOCK' | 'PASS'>>>({});
  const [attempt, setAttempt] = useState<Attempt>({ sending: false, refusal: null, reason: null });
  // The steps of the run this page sent: a composed run's key is not a case key, so its plan is kept here.
  const [sent, setSent] = useState<{ readonly liveRunId: string; readonly steps: number } | null>(null);
  const config = useLiveConfig();
  const {
    container: turnstileContainer,
    token: turnstileToken,
    required: turnstileRequired,
    reset: resetTurnstile,
  } = useTurnstile(config.data?.turnstileSiteKey ?? null);
  const live = useLiveRun(true);
  const current = live.data ?? null;
  const running = current !== null && ACTIVE.has(current.status) ? current : null;
  const currentStatus = current?.status ?? null;
  const currentId = current?.liveRunId ?? null;
  // The visitor's own runs are listed again once a run ends, so its result, comparison and assessment appear.
  useEffect(() => {
    if (currentStatus && !ACTIVE.has(currentStatus)) {
      void queryClient.invalidateQueries({ queryKey: ['lab-recent'] });
    }
  }, [currentStatus, currentId, queryClient]);
  if (!designed || !conditions) {
    return null;
  }
  const changed = FIELDS.filter((field) => conditions[field] !== designed.conditions[field]);
  const choose = (key: string) => {
    const next = options.cases.find((candidate) => candidate.key === key);
    setCaseKey(key);
    setConditions(next?.conditions ?? null);
  };

  async function send() {
    if (!call || !designed || !conditions) {
      return;
    }
    setAttempt({ sending: true, refusal: null, reason: null });
    const only =
      changed.length === 0 ? null : Object.fromEntries(changed.map((field) => [field, conditions[field]]));
    let response;
    try {
      response = await startLabRun(designed.key, only, { call, approaches }, turnstileToken);
    } catch {
      // No answer the page can read (the portal unreachable, or a refusal without a JSON body).
      resetTurnstile();
      setAttempt({ sending: false, refusal: 'error', reason: null });
      return;
    }
    resetTurnstile();
    if (response.status === 202 && response.body) {
      queryClient.setQueryData(['live-run'], response.body.run);
      setSent({ liveRunId: response.body.run.liveRunId, steps: designed.steps });
      void queryClient.invalidateQueries({ queryKey: ['live-run'] });
      setAttempt({ sending: false, refusal: null, reason: null });
      // Every run is called afresh before it is sent (review R-25).
      setCall(null);
      setApproaches({});
      return;
    }
    const reason = response.body?.reason ?? null;
    setAttempt({ sending: false, refusal: refusalOf(response.status, reason), reason });
  }

  const ready =
    call !== null &&
    running === null &&
    !attempt.sending &&
    !(turnstileRequired && !turnstileToken) &&
    config.data?.paused !== true;
  return (
    <div className={styles.lab}>
      <ComposeColumn
        options={options}
        designed={designed}
        conditions={conditions}
        changed={changed}
        onCase={choose}
        onChange={(field, value) => setConditions({ ...conditions, [field]: value })}
      />
      <div className={styles.flow}>
        <section className={styles.section} aria-labelledby="judge-title">
          <JudgeSection
            steps={designed.steps}
            call={call}
            onCall={setCall}
            approaches={approaches}
            onApproach={(control, value) => {
              // An approach without an expectation is left out of the call, not sent as empty.
              const others = Object.fromEntries(
                Object.entries(approaches).filter(([key]) => key !== control),
              ) as Partial<Record<ControlId, 'BLOCK' | 'PASS'>>;
              setApproaches(value ? { ...others, [control]: value } : others);
            }}
          />
          {turnstileRequired ? <div ref={turnstileContainer} /> : null}
          <button type="button" className={styles.send} disabled={!ready} onClick={() => void send()}>
            {t('lab.judge.send', { n: designed.steps, count: designed.steps })}
          </button>
          <SendNote
            steps={designed.steps}
            call={call}
            busy={running !== null}
            remaining={config.data?.remainingToday ?? null}
          />
          {attempt.refusal ? (
            <StateScreen
              kind={
                attempt.refusal === 'dailyLimit'
                  ? 'dailyLimit'
                  : attempt.refusal === 'paused'
                    ? 'paused'
                    : 'outage'
              }
              {...(attempt.refusal === 'error' || attempt.refusal === 'turnstile'
                ? { onRetry: () => void send() }
                : {})}
              {...(attempt.reason ? { cause: attempt.reason } : {})}
            />
          ) : null}
        </section>
        {running ? (
          <RunSection
            view={running}
            plannedSteps={
              sent?.liveRunId === running.liveRunId
                ? sent.steps
                : (options.cases.find((candidate) => candidate.key === running.scenario)?.steps ?? null)
            }
            onRestart={() => void send()}
          />
        ) : null}
        {!running && latest ? <ResultSection run={latest} options={options} /> : null}
        {!running && !latest ? <EmptyResult /> : null}
        {!running && latest && previous ? (
          <CompareSection latest={latest} previous={previous} options={options} />
        ) : null}
        {!running && latest ? (
          <AssessPanel
            key={latest.runId}
            runId={latest.runId}
            reasons={options.assessmentReasons}
            number="5"
          />
        ) : null}
      </div>
    </div>
  );
}

function SendNote({
  steps,
  call,
  busy,
  remaining,
}: {
  readonly steps: number;
  readonly call: string | null;
  readonly busy: boolean;
  readonly remaining: number | null;
}) {
  const { t } = useTranslation();
  return (
    <>
      <p className={styles.note}>
        {steps > 1
          ? t('lab.judge.paced', { seconds: (steps - 1) * ALLOW_WINDOW_SECONDS })
          : t('lab.judge.single')}
      </p>
      {call === null ? <p className={styles.note}>{t('lab.judge.callFirst')}</p> : null}
      {busy ? <p className={styles.note}>{t('lab.judge.busy')}</p> : null}
      {remaining !== null ? (
        <p className={styles.note}>{t('lab.judge.remaining', { n: remaining })}</p>
      ) : null}
    </>
  );
}

interface ComposeProps {
  readonly options: LabOptions;
  readonly designed: LabCase;
  readonly conditions: LabConditions;
  readonly changed: readonly (keyof LabConditions)[];
  readonly onCase: (key: string) => void;
  readonly onChange: (field: keyof LabConditions, value: LabConditions[keyof LabConditions]) => void;
}

function ComposeColumn({ options, designed, conditions, changed, onCase, onChange }: ComposeProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const single = designed.steps === 1;
  const choice = (
    field: keyof LabConditions,
    values: readonly (string | number | boolean)[],
    disabled = false,
  ) => (
    <label className={styles.field} data-changed={changed.includes(field) || undefined}>
      <span className={styles.fieldName}>
        {t(`lab.field.${field}`)}
        {changed.includes(field) ? (
          <span className={styles.changedDot} role="img" aria-label={t('lab.changed')} />
        ) : null}
      </span>
      <select
        className={styles.select}
        value={String(conditions[field] ?? '')}
        disabled={disabled}
        onChange={(event) => {
          const raw = event.target.value;
          const value = values.find((candidate) => String(candidate) === raw) ?? null;
          onChange(field, value as LabConditions[keyof LabConditions]);
        }}
      >
        {values.map((value) => (
          <option key={String(value)} value={String(value)}>
            {valueText(field, value, options, t)}
          </option>
        ))}
      </select>
    </label>
  );
  return (
    <section className={styles.compose} aria-labelledby="compose-title">
      <h2 id="compose-title" className={styles.sectionTitle}>
        <span className={styles.sectionNumber}>1</span>
        {t('lab.compose.title')}
      </h2>
      <label className={styles.field}>
        <span className={styles.fieldName}>{t('lab.compose.case')}</span>
        <select
          className={styles.select}
          value={designed.key}
          onChange={(event) => onCase(event.target.value)}
        >
          {options.cases.map((candidate) => (
            <option key={candidate.key} value={candidate.key}>
              {candidate.key} · {candidate.title[language]}
            </option>
          ))}
        </select>
      </label>
      <p className={styles.note}>{t('lab.compose.truthHidden')}</p>

      <fieldset className={styles.employees}>
        <legend className={styles.fieldName}>{t('lab.field.employee')}</legend>
        {options.employees.map((employee) => (
          <label
            key={employee.key}
            className={styles.employee}
            data-selected={conditions.employee === employee.key || undefined}
          >
            <input
              type="radio"
              name="employee"
              checked={conditions.employee === employee.key}
              onChange={() => onChange('employee', employee.key)}
            />
            <span className={styles.employeeName}>{employee.displayName}</span>
            <span className={styles.note}>
              {t('lab.compose.employeeLine', {
                role: t(`lab.role.${employee.role}`),
                projects: employee.assignedProjects.join(', ') || '-',
              })}
            </span>
          </label>
        ))}
      </fieldset>
      {conditions.employee ? <Baseline employee={conditions.employee} /> : null}

      <div className={styles.fields}>
        {choice(
          'timeSlot',
          options.timeSlots.map((slot) => slot.slot),
        )}
        {choice('place', ['OFFICE', 'TRAVEL', 'EXTERNAL'])}
        {choice('device', ['USUAL', 'NEW'])}
        {choice('operation', options.operations, !single)}
        {choice('target', ['ASSIGNED', 'UNASSIGNED'], !single)}
        {choice('items', options.items, !single)}
        {choice('approval', [false, true])}
        {choice('ticket', ['NONE', 'COVERS', 'OTHER_PROJECT'])}
        {choice('claim', ['NONE', 'REAL', 'FAKE'], !single)}
        {choice('onCall', [false, true])}
      </div>
      {!single ? <p className={styles.note}>{t('lab.compose.stepsFixed', { n: designed.steps })}</p> : null}

      <div className={styles.changedBox} data-composed={changed.length > 0 || undefined}>
        {changed.length === 0 ? (
          <p>{t('lab.compose.asDesigned')}</p>
        ) : (
          <>
            <p className={styles.changedTitle}>{t('lab.compose.changedCount', { n: changed.length })}</p>
            <p>{changed.map((field) => t(`lab.field.${field}`)).join(' · ')}</p>
            <p className={styles.note}>{t('lab.compose.noTruth')}</p>
          </>
        )}
      </div>
    </section>
  );
}

/** What the engine learned about the chosen employee: the template's learned requests (/api/live/baseline). */
function Baseline({ employee }: { readonly employee: string }) {
  const { t } = useTranslation();
  const baseline = useBaseline(employee);
  if (!baseline.data) {
    return <p className={styles.note}>{baseline.isError ? t('lab.baseline.none') : t('anatomy.loading')}</p>;
  }
  const learned = baseline.data.learned;
  const peak = Math.max(1, ...learned.hours);
  return (
    <div className={styles.baseline} role="group" aria-labelledby="baseline-title">
      <p id="baseline-title" className={styles.fieldName}>
        {t('lab.baseline.title', { n: learned.requests })}
      </p>
      <div className={styles.hours} role="img" aria-label={t('lab.baseline.hoursAria')}>
        {learned.hours.map((count, hour) => (
          <span
            key={hour}
            className={styles.hour}
            data-active={count > 0 || undefined}
            style={{ blockSize: `${count === 0 ? 8 : 20 + (count / peak) * 80}%` }}
          />
        ))}
      </div>
      <p className={styles.hourAxis}>
        <span>0</span>
        <span>6</span>
        <span>12</span>
        <span>18</span>
        <span>23</span>
      </p>
      <dl className={styles.baselineFacts}>
        <div>
          <dt>{t('lab.baseline.networks')}</dt>
          <dd className={styles.mono}>{learned.networks.join(', ') || '-'}</dd>
        </div>
        <div>
          <dt>{t('lab.baseline.devices')}</dt>
          <dd className={styles.mono}>{learned.devices.join(', ') || '-'}</dd>
        </div>
      </dl>
      <p className={styles.note}>{t('lab.baseline.source', { template: baseline.data.templateId })}</p>
    </div>
  );
}

interface JudgeProps {
  readonly steps: number;
  readonly call: string | null;
  readonly onCall: (call: LabPrediction['call']) => void;
  readonly approaches: Partial<Record<ControlId, 'BLOCK' | 'PASS'>>;
  readonly onApproach: (control: ControlId, value: 'BLOCK' | 'PASS' | null) => void;
}

/** Activity 2: the visitor's call before anything is sent, and, optionally, what each approach will do. */
function JudgeSection({ call, onCall, approaches, onApproach }: JudgeProps) {
  const { t } = useTranslation();
  return (
    <>
      <h2 id="judge-title" className={styles.sectionTitle}>
        <span className={styles.sectionNumber}>2</span>
        {t('lab.judge.title')}
      </h2>
      <fieldset className={styles.calls}>
        <legend className={styles.fieldName}>{t('lab.judge.question')}</legend>
        {(['NORMAL', 'ATTACK', 'UNSURE'] as const).map((value) => (
          <label key={value} className={styles.callChoice} data-selected={call === value || undefined}>
            <input type="radio" name="call" checked={call === value} onChange={() => onCall(value)} />
            {t(`lab.call.${value}`)}
          </label>
        ))}
      </fieldset>
      <details className={styles.expectations}>
        <summary>{t('lab.judge.perApproach')}</summary>
        <ul className={styles.approachList}>
          {CONTROL_ORDER.map((control) => (
            <li key={control}>
              <span className={styles.approachName}>{t(`control.${control}.name`)}</span>
              <span className={styles.note}>{t(`control.${control}.config`)}</span>
              <label className={styles.expectChoice}>
                <span className={styles.visuallyHidden}>
                  {t('lab.judge.expectLabel', { approach: t(`control.${control}.name`) })}
                </span>
                <select
                  className={styles.select}
                  value={approaches[control] ?? ''}
                  onChange={(event) =>
                    onApproach(
                      control,
                      event.target.value === '' ? null : (event.target.value as 'BLOCK' | 'PASS'),
                    )
                  }
                >
                  <option value="">{t('lab.expect.none')}</option>
                  <option value="BLOCK">{t('lab.expect.BLOCK')}</option>
                  <option value="PASS">{t('lab.expect.PASS')}</option>
                </select>
              </label>
            </li>
          ))}
        </ul>
      </details>
    </>
  );
}

function EmptyResult() {
  const { t } = useTranslation();
  return (
    <section className={styles.section}>
      <p className={styles.note}>{t('lab.result.empty')}</p>
    </section>
  );
}

/**
 * Activity 3 while the run goes: each request as it is sent, each approach's answer as it arrives, and the engine's
 * analysis of the latest request with the time of each stage (T-5). Nothing is judged here: the words are the stored
 * outcomes and the engine's own stage names.
 */
function RunSection({
  view,
  plannedSteps,
  onRestart,
}: {
  readonly view: LiveRunView;
  readonly plannedSteps: number | null;
  readonly onRestart: () => void;
}) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const lastStep = view.steps[view.steps.length - 1]?.stepNo ?? 1;
  const analysing = view.status !== 'QUEUED' && view.status !== 'STARTING';
  const analysis = useLiveAnalysis(view.liveRunId, lastStep, analysing);
  const act = async (path: string, body: unknown = {}) => {
    await postJson(path, body);
    void queryClient.invalidateQueries({ queryKey: ['live-run'] });
  };
  return (
    <section className={styles.section} aria-labelledby="run-title">
      <h2 id="run-title" className={styles.sectionTitle}>
        <span className={styles.sectionNumber}>3</span>
        {t('lab.run.title')}
      </h2>
      <p className={styles.runStatus} role="status">
        {t(`lab.run.status.${view.status}`, {
          position: view.queuePosition,
          step: view.awaitingStep ?? lastStep,
        })}
      </p>
      {view.status === 'AWAITING' ? (
        <button type="button" className={styles.send} onClick={() => void act('/api/live/runs/current/next')}>
          {t('lab.run.next', { n: view.awaitingStep ?? lastStep + 1 })}
        </button>
      ) : null}
      {view.challenge ? (
        <LiveChallenge
          challenge={view.challenge}
          onRequestCode={() => void act('/api/live/runs/current/code')}
          onAnswer={(code) => void act('/api/live/runs/current/answer', { code })}
          onCancel={() => void act('/api/live/runs/current/cancel')}
          onRestart={onRestart}
        />
      ) : null}
      {view.status === 'BLOCKED' ? (
        <button
          type="button"
          className={styles.send}
          onClick={() => void act('/api/live/runs/current/abandon')}
        >
          {t('lab.run.endBlocked')}
        </button>
      ) : null}
      <ol className={styles.runSteps}>
        {view.steps.map((step) => (
          <li key={step.stepNo} className={styles.runStep}>
            <p className={styles.runStepHead}>
              {t('lab.result.step', { n: step.stepNo })}
              {step.operation ? <span className={styles.mono}>{step.operation}</span> : null}
            </p>
            <ul className={styles.runCells}>
              {CONTROL_ORDER.map((control) => {
                const layer = step.layers[control];
                const stream = step.streams?.[control];
                return (
                  <li key={control} className={styles.runCell} data-arrived={layer ? true : undefined}>
                    <span className={styles.approachName}>{t(`control.${control}.name`)}</span>
                    <span className={layer ? styles.outcome : styles.muted} data-outcome={layer?.outcome}>
                      {layer
                        ? t(OUTCOME_KEYS[layer.outcome])
                        : stream
                          ? t('lab.run.streaming', {
                              delivered: stream.delivered,
                              total: stream.total ?? '-',
                            })
                          : t('lab.run.waiting')}
                    </span>
                    {layer ? (
                      <span className={styles.mono}>
                        {t('lab.run.answer', {
                          status: layer.httpStatus ?? '-',
                          ms: layer.elapsedMs,
                          items: layer.deliveredItems.toLocaleString(i18n.language),
                        })}
                      </span>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          </li>
        ))}
      </ol>
      <AnalysisStages stages={analysis.data?.stages ?? []} step={lastStep} />
      {plannedSteps !== null && plannedSteps > 1 && view.status === 'RUNNING' ? (
        <p className={styles.note}>{t('lab.run.paceNote')}</p>
      ) : null}
    </section>
  );
}

/** The engine's analysis stages of one request as the engine reported them, timed from when it received it. */
function AnalysisStages({
  stages,
  step,
}: {
  readonly stages: readonly AnalysisStage[];
  readonly step: number;
}) {
  const { t } = useTranslation();
  const shown = stages.filter((stage) => ANALYSIS_SHOWN.has(stage.type));
  return (
    <div className={styles.block} aria-live="polite">
      <h3 className={styles.blockTitle}>{t('lab.run.analysis', { n: step })}</h3>
      {shown.length === 0 ? (
        <p className={styles.note}>{t('lab.run.analysisNone')}</p>
      ) : (
        <ol className={styles.stages}>
          {shown.map((stage, index) => (
            <li key={`${stage.type}-${index}`} className={styles.stage}>
              <span>{t(`show.analysis.stage.${stage.type}`)}</span>
              {stage.action ? <span className={styles.mono}>{stage.action}</span> : null}
              <span className={styles.mono}>
                {stage.atMs === null ? '' : t('anatomy.plusMs', { ms: stage.atMs })}
              </span>
            </li>
          ))}
        </ol>
      )}
      <p className={styles.note}>{t('lab.run.analysisSource')}</p>
    </div>
  );
}

/**
 * What an approach actually did in a run, step by step (pass, stop, hold...), from the stored step results: the same
 * words whether or not the run has a ground truth.
 */
function outcomeLine(results: readonly (StepResult | undefined)[], control: ControlId, t: TFunction): string {
  if (results.length === 0 || results.some((result) => !result)) {
    return '-';
  }
  const words = results.map((result) => {
    const layer = result?.layers.find((candidate) => candidate.control === control);
    return layer ? t(OUTCOME_KEYS[layer.outcome]) : '-';
  });
  return words.length === 1
    ? (words[0] ?? '-')
    : words.map((word, index) => t('lab.result.stepOutcome', { n: index + 1, outcome: word })).join(' · ');
}

/** "2026-09-30T03:17:00Z" as "2026-09-30 03:17"; company time is UTC (CompanyCalendar). */
function companyTime(value: string): string {
  return value.replace('T', ' ').replace(/:00(\.\d+)?Z$/, '');
}

function businessCorrectCount(score: RunScore): number {
  return CONTROL_ORDER.filter((control) => score.correct[control] === true).length;
}

function ResultSection({ run, options }: { readonly run: RecentLabRun; readonly options: LabOptions }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const score = useRunScore(run.runId, 'lab', 0);
  const [step, setStep] = useState(1);
  const steps = score.data?.executedSteps ?? 1;
  const result = useStepResult(run.runId, step);
  const labCase = options.cases.find((candidate) => candidate.key === run.caseKey);
  const contexa = score.data?.business.D;
  const all = useRunStepResults(run.runId, steps);
  return (
    <section className={styles.section} aria-labelledby="result-title">
      <h2 id="result-title" className={styles.sectionTitle}>
        <span className={styles.sectionNumber}>3</span>
        {t('lab.result.title')}
      </h2>
      <p className={styles.note}>
        {t('lab.result.runLine', { run: run.runId, case: labCase?.title[language] ?? run.caseKey })}
      </p>
      {score.data ? (
        <p className={styles.conclusion}>
          {run.designed
            ? t('lab.result.designedConclusion', {
                truth: t(`anatomy.class.${score.data.truth.classification ?? 'NONE'}`),
                right: businessCorrectCount(score.data),
                contexa: contexa
                  ? t(`score.result.${contexa.result}`, {
                      n: contexa.exposedItems,
                      count: contexa.exposedItems,
                    })
                  : '-',
              })
            : t('lab.result.composedConclusion', {
                call: run.call ? t(`lab.call.${run.call}`) : t('lab.value.none'),
                contexa: outcomeLine(all, 'D', t),
              })}
        </p>
      ) : null}
      {run.call ? (
        <p className={styles.note}>{t('lab.result.yourCall', { call: t(`lab.call.${run.call}`) })}</p>
      ) : null}
      {steps > 1 ? (
        <div className={styles.tabs} role="tablist" aria-label={t('lab.result.stepsLabel')}>
          {Array.from({ length: steps }, (_, index) => index + 1).map((number) => (
            <button
              key={number}
              type="button"
              role="tab"
              aria-selected={step === number}
              className={styles.tab}
              onClick={() => setStep(number)}
            >
              {t('lab.result.step', { n: number })}
            </button>
          ))}
        </div>
      ) : null}
      {result.data ? (
        <>
          <p className={styles.note}>
            {t('lab.result.companyTime', { time: companyTime(result.data.companyTime) })}
          </p>
          <ApproachResults layers={result.data.layers} expected={run.approaches} />
          <Link className={styles.anatomyLink} to={`/runs/${run.runId}/steps/${step}`}>
            {t('lab.result.openAnatomy')}
          </Link>
        </>
      ) : null}
    </section>
  );
}

function CompareSection({
  latest,
  previous,
  options,
}: {
  readonly latest: RecentLabRun;
  readonly previous: RecentLabRun;
  readonly options: LabOptions;
}) {
  const { t } = useTranslation();
  const now = useRunScore(latest.runId, 'lab', 0);
  const before = useRunScore(previous.runId, 'lab', 0);
  const nowResults = useRunStepResults(latest.runId, now.data?.executedSteps ?? 0);
  const beforeResults = useRunStepResults(previous.runId, before.data?.executedSteps ?? 0);
  const fields = FIELDS.filter(
    (field) => latest.conditions[field] !== undefined || previous.conditions[field] !== undefined,
  );
  return (
    <section className={styles.section} aria-labelledby="compare-title">
      <h2 id="compare-title" className={styles.sectionTitle}>
        <span className={styles.sectionNumber}>4</span>
        {t('lab.compare.title')}
      </h2>
      <p className={styles.note}>{t('lab.compare.lead', { before: previous.runId, now: latest.runId })}</p>
      <div className={styles.compareGrid}>
        <div className={styles.compareSide}>
          <h3 className={styles.blockTitle}>{t('lab.compare.conditions')}</h3>
          <ul className={styles.diffList}>
            {fields.map((field) => {
              const same = latest.conditions[field] === previous.conditions[field];
              return (
                <li key={field} data-same={same || undefined}>
                  <span className={styles.diffName}>{t(`lab.field.${field}`)}</span>
                  <span className={styles.diffValues}>
                    {same
                      ? valueText(field, latest.conditions[field], options, t)
                      : `${valueText(field, previous.conditions[field], options, t)} → ${valueText(field, latest.conditions[field], options, t)}`}
                  </span>
                  <span className={styles.diffState}>
                    {t(same ? 'lab.compare.same' : 'lab.compare.changed')}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
        <div className={styles.compareSide}>
          <h3 className={styles.blockTitle}>{t('lab.compare.results')}</h3>
          <ul className={styles.diffList}>
            {CONTROL_ORDER.map((control) => {
              const was = outcomeLine(beforeResults, control, t);
              const is = outcomeLine(nowResults, control, t);
              const same = was === is;
              return (
                <li key={control} data-same={same || undefined}>
                  <span className={styles.diffName}>{t(`control.${control}.name`)}</span>
                  <span className={styles.diffValues}>{same ? is : `${was} → ${is}`}</span>
                  <span className={styles.diffState}>
                    {t(same ? 'lab.compare.same' : 'lab.compare.changed')}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      </div>
      <InputDiff before={previous.runId} now={latest.runId} />
      <p className={styles.note}>{t('lab.compare.noCause')}</p>
    </section>
  );
}

/** One item of the engine input: what the engine was told about the first request, from the stored anatomy. */
function inputItems(anatomy: DecisionAnatomyView | undefined): Map<string, string> {
  const items = new Map<string, string>();
  if (!anatomy) {
    return items;
  }
  for (const row of anatomy.context.usualVsNow) {
    items.set(`dim.${row.dimension}`, `${row.now ?? '-'} · ${row.inUsual ?? '-'}`);
  }
  const company = anatomy.context.company;
  items.set('ApprovalRequired', String(company?.approvalRequired ?? '-'));
  items.set('ApprovalMissing', String(company?.approvalMissing ?? '-'));
  items.set('ApprovalStatus', String(company?.approvalStatus ?? '-'));
  items.set('Sensitivity', String(anatomy.context.resource?.sensitivity ?? '-'));
  items.set('CurrentVsObservedDeltaCount', anatomy.context.labelMatrix['CurrentVsObservedDeltaCount'] ?? '-');
  return items;
}

/**
 * Where the engine input of the first request differed between the two runs (review R-15): the comparison shows the
 * input the engine received, not only the conditions the visitor chose, and claims no cause.
 */
function InputDiff({ before, now }: { readonly before: string; readonly now: string }) {
  const { t } = useTranslation();
  const was = useAnatomy(before, 1);
  const is = useAnatomy(now, 1);
  if (!was.data || !is.data) {
    return null;
  }
  const a = inputItems(was.data);
  const b = inputItems(is.data);
  const keys = [...new Set([...a.keys(), ...b.keys()])].filter((key) => a.get(key) !== b.get(key));
  return (
    <div className={styles.compareSide}>
      <h3 className={styles.blockTitle}>{t('lab.compare.input', { n: keys.length })}</h3>
      {keys.length === 0 ? (
        <p className={styles.note}>{t('lab.compare.inputSame')}</p>
      ) : (
        <ul className={styles.diffList}>
          {keys.map((key) => (
            <li key={key}>
              <span className={styles.diffName}>
                {key.startsWith('dim.') ? t(`anatomy.dim.${key.slice(4)}`) : key}
              </span>
              <span className={`${styles.diffValues} ${styles.mono}`}>
                {a.get(key) ?? '-'} → {b.get(key) ?? '-'}
              </span>
              <span className={styles.diffState}>{t('lab.compare.changed')}</span>
            </li>
          ))}
        </ul>
      )}
      <p className={styles.note}>{t('lab.compare.inputSource')}</p>
    </div>
  );
}
