import { useTranslation } from 'react-i18next';
import type { AnatomyCall, DecisionAnatomyView } from '../../api/anatomy';
import type { AnalysisStage, DecisionWait, LiveDecision } from '../../api/types';
import { formatDuration, formatNumber } from '../format';
import { Bar, Icon } from '../ui';
import { UX_VERDICTS } from '../verdict';
import { verdictOf } from './person';
import styles from './Live.module.css';

type RowState = 'done' | 'now' | 'wait' | 'error';

interface Row {
  readonly id: 'context' | 'baseline' | 'prompt' | 'model' | 'applied';
  readonly state: RowState;
  /** Milliseconds after control D received the request, as the engine recorded it; null when the record has none. */
  readonly at: number | null;
  readonly detail: string | null;
}

interface DecisionProgressProps {
  readonly stages: readonly AnalysisStage[];
  readonly decision: LiveDecision | null;
  readonly wait: DecisionWait | null;
  /** The stored step's anatomy once the run is recorded: the learned baseline, the prompt's lines, the model. */
  readonly anatomy: DecisionAnatomyView | null;
  /** The business records and the baseline comparison the engine received (the run's own once stored). */
  readonly context: readonly string[];
  readonly compared: number | null;
  readonly departed: number | null;
  /** Control D's HTTP status once it answered. */
  readonly httpStatus: number | null;
  /** The request the panel follows in a case of several requests; null for a case of one. */
  readonly step: number | null;
  /** The latest measurement's runs of the same scenario and Contexa's decisions in them (/api/benchmark); null without. */
  readonly measured?: Measured | null;
}

/** The latest measurement of the scenario as the portal counts it: its runs and Contexa's decisions by action. */
export interface Measured {
  readonly runs: number;
  readonly actions: Readonly<Record<string, number>>;
}

const has = (stages: readonly AnalysisStage[], type: string) =>
  stages.find((stage) => stage.type === type) ?? null;

/**
 * What Contexa checks while the decision takes its seconds (기획안 F-5): the business context, the behavioural baseline,
 * the decision prompt, the model's inference and the decision applied. Each row is lit by the engine's own events as
 * they arrive (/api/live/runs/current/analysis); the details come from the run's record once it is stored, and a row
 * whose record has no time shows none.
 */
export function DecisionProgress({
  stages,
  decision,
  wait,
  anatomy,
  context,
  compared,
  departed,
  httpStatus,
  step,
  measured = null,
}: DecisionProgressProps) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const collected = has(stages, 'CONTEXT_COLLECTED');
  const started = has(stages, 'LAYER1_START');
  const completed = has(stages, 'LAYER2_COMPLETE') ?? has(stages, 'LAYER1_COMPLETE');
  const applied = has(stages, 'DECISION_APPLIED');
  const failed = has(stages, 'ANALYSIS_ERROR');
  const call = anatomy?.interpretation?.calls[0] ?? null;
  const lines = anatomy?.promptLines ?? null;
  const learned = anatomy?.figures.baselineBefore ?? null;
  const rows: readonly Row[] = [
    {
      id: 'context',
      state: collected ? 'done' : 'now',
      at: collected?.atMs ?? null,
      detail: context.length > 0 ? context.join(' · ') : null,
    },
    {
      id: 'baseline',
      state: collected ? 'done' : 'wait',
      at: null,
      detail:
        compared !== null && departed !== null
          ? learned !== null
            ? t('ux.live.stage.baselineLearned', {
                learned: n(learned),
                compared: n(compared),
                departed: n(departed),
              })
            : t('ux.live.stage.baselineCompared', { compared: n(compared), departed: n(departed) })
          : null,
    },
    {
      id: 'prompt',
      state: started ? 'done' : collected ? 'now' : 'wait',
      at: null,
      detail: lines ? t('ux.live.stage.promptLines', { system: n(lines.system), user: n(lines.user) }) : null,
    },
    {
      id: 'model',
      state: failed ? 'error' : completed ? 'done' : started ? 'now' : 'wait',
      at: completed?.elapsedMs ?? null,
      detail: failed
        ? t('ux.live.stage.error')
        : [
            call?.model ?? null,
            decision
              ? t('ux.live.stage.tokens', {
                  input: n(decision.promptTokens),
                  output: n(decision.completionTokens),
                })
              : null,
            completed?.riskScore != null
              ? t('ux.live.stage.scores', {
                  risk: completed.riskScore.toFixed(2),
                  confidence: completed.confidence?.toFixed(2) ?? '—',
                })
              : null,
          ]
            .filter((part): part is string => part !== null)
            .join(' · ') || null,
    },
    {
      id: 'applied',
      state: applied ? 'done' : failed ? 'error' : 'wait',
      at: applied?.atMs ?? null,
      detail: applied
        ? [
            decision ? t(`ux.live.applied.${decision.applied}`) : null,
            httpStatus !== null ? `HTTP ${httpStatus}` : null,
          ]
            .filter((part): part is string => part !== null)
            .join(' · ')
        : null,
    },
  ];
  return (
    <section className={styles.progress} aria-labelledby="progress-title">
      <h2 id="progress-title" className={styles.progressTitle}>
        {t('ux.live.progress.title')}
      </h2>
      <p className={styles.progressSub}>
        {step === null ? t('ux.live.progress.sub') : t('ux.live.progress.subStep', { n: step })}
      </p>
      <ol className={styles.stages}>
        {rows.map((row, index) => (
          <li key={row.id} className={styles.stage} data-state={row.state}>
            <span className={styles.stageMark} aria-hidden="true">
              {row.state === 'done' ? (
                <Icon name="check" size="sm" />
              ) : row.state === 'error' ? (
                <Icon name="x" size="sm" />
              ) : (
                index + 1
              )}
            </span>
            <div className={styles.stageBody}>
              <b>{t(`ux.live.stage.${row.id}`)}</b>
              <span className="ux-sr-only">{t(`ux.live.state.${row.state}`)}</span>
              {row.detail ? <p className={styles.stageDetail}>{row.detail}</p> : null}
              {row.id === 'model' && row.state === 'now' && wait ? (
                <Bar
                  label={t('ux.live.stage.model')}
                  value={Math.min(1, wait.waitedMs / Math.max(wait.medianMs, 1))}
                  tone="link"
                />
              ) : null}
            </div>
            <span className={styles.stageAt}>
              {row.at !== null ? t('ux.time.seconds', { value: formatDuration(row.at, i18n.language) }) : ''}
            </span>
          </li>
        ))}
      </ol>
      {wait && !completed ? (
        <p className={styles.progressNote}>
          {t('ux.live.median', {
            seconds: formatDuration(wait.medianMs, i18n.language),
            n: n(wait.decisions),
          })}
        </p>
      ) : null}
      <EngineLog stages={stages} calls={anatomy?.interpretation?.calls ?? []} measured={measured} />
    </section>
  );
}

/**
 * The engine's record behind the rows, folded (P-8): each analysis event at the time the engine recorded it, with the
 * action, risk and confidence a pass closed with; each model call's time and tokens; and the latest measurement's
 * runs of the same scenario with Contexa's decisions in them. Every value is the record's own; nothing when it has none.
 */
function EngineLog({
  stages,
  calls,
  measured,
}: {
  readonly stages: readonly AnalysisStage[];
  readonly calls: readonly AnatomyCall[];
  readonly measured: Measured | null;
}) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const seconds = (ms: number | null) => (ms === null ? '—' : formatDuration(ms, i18n.language));
  const secondPass = stages.some((stage) => stage.type.startsWith('LAYER2_'));
  const decided = Object.entries(measured?.actions ?? {}).filter(([, count]) => count > 0);
  if (stages.length === 0 && calls.length === 0 && measured === null) {
    return null;
  }
  const eventName = (type: string) =>
    secondPass && type.startsWith('LAYER1_')
      ? t(`ux.live.log.first.${type}`, { defaultValue: type })
      : t(`ux.live.log.event.${type}`, { defaultValue: type });
  return (
    <details className={styles.logMore}>
      <summary>{t('ux.live.log.more')}</summary>
      {stages.length > 0 ? (
        <>
          <p className={styles.logHead}>{t('ux.live.log.events')}</p>
          <ol className={styles.log}>
            {stages.map((stage, index) => (
              <li key={`${stage.type}-${index}`}>
                <span>
                  {[
                    eventName(stage.type),
                    stage.type.endsWith('_COMPLETE') ? stage.action : null,
                    stage.type.endsWith('_COMPLETE') && stage.riskScore !== null
                      ? t('ux.live.stage.scores', {
                          risk: stage.riskScore.toFixed(2),
                          confidence: stage.confidence?.toFixed(2) ?? '—',
                        })
                      : null,
                  ]
                    .filter((part): part is string => part !== null)
                    .join(' · ')}
                </span>
                <span className={styles.logAt}>
                  {stage.atMs !== null ? t('ux.live.log.at', { seconds: seconds(stage.atMs) }) : '—'}
                </span>
              </li>
            ))}
          </ol>
        </>
      ) : null}
      {calls.length > 0 ? (
        <>
          <p className={styles.logHead}>{t('ux.live.log.calls')}</p>
          <ul className={styles.log}>
            {calls.map((call) => (
              <li key={call.callNo}>
                <span>
                  {t('ux.live.log.call', {
                    n: call.callNo,
                    seconds: seconds(call.elapsedMs),
                    input: call.promptTokens === null ? '—' : n(call.promptTokens),
                    output: call.completionTokens === null ? '—' : n(call.completionTokens),
                  })}
                </span>
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {measured ? (
        <p className={styles.logMeasured}>
          {t('ux.live.log.measured', {
            runs: n(measured.runs),
            list:
              decided
                .map(([action, count]) =>
                  t('ux.live.log.action', {
                    verdict: t(UX_VERDICTS[verdictOf(action)].labelKey),
                    n: n(count),
                  }),
                )
                .join(' · ') || '—',
          })}
        </p>
      ) : null}
    </details>
  );
}
