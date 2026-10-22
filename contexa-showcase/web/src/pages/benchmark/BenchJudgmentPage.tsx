import { useTranslation } from 'react-i18next';
import type { BenchmarkView, JudgmentTimingKind } from '../../api/benchmark';
import { useUrlModal } from '../../components/common/useUrlModal';
import { VERDICTS, type VerdictPresentation } from '../../domain/verdict';
import { count, dollars, seconds } from '../../journey/format';
import { BenchScreen, BenchSource } from './BenchScreen';
import { caseName, useBenchView } from './benchData';
import { BENCH_MODALS } from './benchPlace';
import { judgmentOthers, riskKinds, type JudgmentRun, type JudgmentStep } from './benchShapes';
import { Histogram } from './charts/Histogram';
import { StackBar, type StackTone } from './charts/StackBar';
import styles from './Bench.module.css';

type Translate = ReturnType<typeof useTranslation>['t'];

/** The kinds in the bar's order, each with its tone: the check before analysis is not Contexa's judgement. */
const KINDS: readonly (readonly [JudgmentTimingKind, StackTone])[] = [
  ['STATIC_REFUSAL', 'neutral'],
  ['BEFORE_RESPONSE', 'safe'],
  ['NEXT_REQUEST', 'partial'],
  ['JUDGED_ALLOW', 'loss'],
  ['OTHER', 'otherHatch'],
];

/** A step's decision in the visitors' word for it, the action itself where it is none of the four. */
function verdictWord(t: Translate, action: string): string {
  const found = (VERDICTS as Readonly<Record<string, VerdictPresentation | undefined>>)[action];
  return found ? t(found.labelKey) : action;
}

/** When a step's decision applied, in words; a decision from the next request after the last step says so. */
function appliedWord(t: Translate, step: JudgmentStep): string {
  if (step.applied === 'NEXT_REQUEST' && !step.applicable) {
    return t('bench.r7.judgment.applied.late');
  }
  return t(`bench.r7.judgment.applied.${step.applied}`, { defaultValue: step.applied });
}

/**
 * A run's steps in words, as the portal scored them: each decision with when it applied, and the steps answered without
 * a decision of their own (refused by an earlier decision, by the sign-in check, or not judged), runs of the same such
 * answer written once ("요청 3~5").
 */
function stepWords(t: Translate, steps: readonly JudgmentStep[]): string {
  const words: string[] = [];
  for (let at = 0; at < steps.length; at++) {
    const step = steps[at] as JudgmentStep;
    if (step.action !== null) {
      words.push(
        t('bench.r7.judgment.step.decided', {
          n: step.stepNo,
          verdict: verdictWord(t, step.action),
          applied: appliedWord(t, step),
        }),
      );
      continue;
    }
    let last = step;
    while (at + 1 < steps.length) {
      const next = steps[at + 1] as JudgmentStep;
      if (next.action !== null || next.source !== step.source) {
        break;
      }
      last = next;
      at++;
    }
    const n = last === step ? String(step.stepNo) : `${step.stepNo}~${last.stepNo}`;
    words.push(t(`bench.r7.judgment.step.${step.source}`, { n, defaultValue: `${n} ${step.source}` }));
  }
  return words.join(' · ');
}

/**
 * V-01 of docs/showcase/영상전-검토.md: the runs of the kind "other", each worded from the shape the portal sent (the
 * case, every step's decision and when it applied, the result and the items that leaked), never a fixed sentence.
 */
function OtherRuns({ view, runs }: { readonly view: BenchmarkView; readonly runs: readonly JudgmentRun[] }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const nameOf = (key: string) => {
    const row = view.cases.find((candidate) => candidate.key === key);
    return row ? caseName(t, row, language) : key;
  };
  const title = t('bench.r7.judgment.othersTitle', { count: view.judgmentTiming.OTHER });
  return (
    <section className={styles.explain}>
      <h2 className={styles.explainTitle}>{title}</h2>
      <ul className={styles.plainList} aria-label={title}>
        {runs.map((run) => (
          <li key={run.runId} data-other-run={run.runId}>
            {t('bench.r7.judgment.other', {
              name: nameOf(run.caseKey),
              steps: stepWords(t, run.steps),
              result: t(`main.result.${run.result}`, { defaultValue: run.result }),
              items: count(run.exposedItems, i18n.language),
            })}
          </li>
        ))}
      </ul>
    </section>
  );
}

/**
 * B-4 of docs/showcase/벤치마크-구현계획.md (a table view): how each attack Contexa received ended, as one 100% bar of
 * the server's counts (refused first by the sign-in check, stopped before the response, stopped from the next request
 * on, judged to pass, other), the "other" runs worded step by step, what the two limits mean in a line each, the risky
 * runs by the bars they sit in, then how long the decisions took (the portal's bins with the median and the 95th
 * percentile) and what one decision costs.
 */
export default function BenchJudgmentPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const method = useUrlModal(BENCH_MODALS.method);
  const { view, empty, state } = useBenchView();
  const timing = view?.judgmentTiming ?? null;
  const engine = view?.engine ?? null;
  const others = view ? judgmentOthers(view) : [];
  const risk = view ? riskKinds(view) : null;
  const nameOf = (key: string) => {
    const row = view?.cases.find((candidate) => candidate.key === key);
    return row ? caseName(t, row, language) : key;
  };
  return (
    <BenchScreen
      view="judgment"
      type="table"
      title={
        view
          ? t('bench.r7.judgment.title', { n: view.scope.attackRuns })
          : t('bench.r7.judgment.titleLoading')
      }
      purpose={t('bench.r7.judgment.guide')}
      sourceLine={
        view && timing ? <BenchSource text={t('frame.source.measured')} onOpen={() => method.show()} /> : null
      }
    >
      {state}
      {empty ? <p className={styles.line}>{t('bench.r7.empty')}</p> : null}
      {view && timing ? (
        <>
          <StackBar
            rows={[
              {
                key: 'D',
                label: t('control.D.name'),
                // "Other" only when the server counted some, as before.
                segments: KINDS.filter(([kind]) => kind !== 'OTHER' || timing.OTHER > 0).map(
                  ([kind, tone]) => ({
                    key: kind,
                    label: t(`bench.r7.judgment.kind.${kind}`),
                    count: timing[kind],
                    tone,
                  }),
                ),
              },
            ]}
            summary={t('bench.r7.judgment.barLabel')}
            rowHead={t('bench.chart.approach')}
            countLabel={(n) => t('benchmark.times', { n })}
          />
          {others.length > 0 ? <OtherRuns view={view} runs={others} /> : null}
          <div className={styles.callouts}>
            <p className={styles.callout}>{t('bench.r7.judgment.timing', { n: timing.NEXT_REQUEST })}</p>
            <p className={styles.callout}>{t('bench.r7.judgment.judged', { n: timing.JUDGED_ALLOW })}</p>
          </div>
          {risk ? (
            <>
              <p className={styles.line}>
                {t('bench.r7.judgment.riskKinds', {
                  runs: view.riskJudged.runs,
                  stopped: view.riskJudged.stopped,
                  kinds: KINDS.filter(([kind]) => (risk.kinds[kind] ?? 0) > 0)
                    .map(([kind]) =>
                      t('bench.r7.judgment.riskKind', {
                        kind: t(`bench.r7.judgment.kind.${kind}`),
                        n: risk.kinds[kind] ?? 0,
                      }),
                    )
                    .join(' · '),
                })}
              </p>
              {risk.notStopped.length > 0 ? (
                <p className={styles.line}>
                  {t('bench.r7.judgment.notStopped', { cases: risk.notStopped.map(nameOf).join(' · ') })}
                </p>
              ) : null}
            </>
          ) : (
            <p className={styles.line}>
              {t('bench.r7.judgment.risk', { runs: view.riskJudged.runs, stopped: view.riskJudged.stopped })}
            </p>
          )}
          {view.judgmentExposure ? (
            <ul className={styles.proofLines} aria-label={t('bench.chart.judgment.exposedTitle')}>
              {KINDS.filter(([kind]) => (view.judgmentExposure?.[kind] ?? 0) > 0).map(([kind]) => (
                <li key={kind} data-exposed={kind}>
                  {t('bench.chart.judgment.exposed', {
                    kind: t(`bench.r7.judgment.kind.${kind}`),
                    items: count(view.judgmentExposure?.[kind] ?? 0, i18n.language),
                  })}
                </li>
              ))}
            </ul>
          ) : null}
          {engine ? (
            <>
              <h2 className={styles.proofTitle}>
                {t('bench.chart.judgment.timeTitle', { n: count(engine.analysisMeasured, i18n.language) })}
              </h2>
              {engine.analysisBins && engine.analysisBins.length > 0 ? (
                <Histogram
                  bins={engine.analysisBins}
                  p50Ms={engine.analysisP50Ms}
                  p95Ms={engine.analysisP95Ms}
                  summary={t('bench.chart.judgment.timeSummary', { n: engine.analysisMeasured })}
                />
              ) : null}
              <p className={styles.line}>
                {t('bench.chart.judgment.times', {
                  p50: engine.analysisP50Ms === null ? '-' : seconds(engine.analysisP50Ms),
                  p95: engine.analysisP95Ms === null ? '-' : seconds(engine.analysisP95Ms),
                  n: count(engine.analysisMeasured, i18n.language),
                })}
              </p>
              {engine.costPerDecisionUsd !== null ? (
                <p className={styles.note}>
                  {t('bench.chart.judgment.cost', {
                    usd: dollars(engine.costPerDecisionUsd),
                    tokens:
                      engine.tokensPerDecision === null
                        ? '-'
                        : count(Math.round(engine.tokensPerDecision), i18n.language),
                    calls:
                      engine.modelCallsPerDecision === null ? '-' : engine.modelCallsPerDecision.toFixed(2),
                  })}
                </p>
              ) : null}
            </>
          ) : null}
        </>
      ) : null}
    </BenchScreen>
  );
}
