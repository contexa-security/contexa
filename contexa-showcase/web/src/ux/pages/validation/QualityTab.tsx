import { useTranslation } from 'react-i18next';
import type { BenchmarkRate, BenchmarkView, JudgmentTimingKind } from '../../../api/benchmark';
import {
  notPublished,
  promptQualityRawHref,
  usePromptQuality,
  type PromptQualityView,
} from '../../../api/promptQuality';
import { formatNumber, formatSeconds, formatUtc } from '../../format';
import { ButtonAnchor, Card, ErrorState, Loading, StackedBar, type BarTone, type Segment } from '../../ui';
import {
  judgmentOthers,
  mostLikelyActions,
  rateCounts,
  ratePercent,
  riskKinds,
  useValidationSetting,
  type JudgmentStep,
} from '../../validation/shapes';
import { useReasonMatch } from '../../validation/hooks';
import { RateText } from './ValidationParts';
import styles from './Validation.module.css';
import { breakable } from '../../ui/breakable';

/** The ends of an attack run in the bar's order, each with its tone: the check before analysis is not Contexa's judgement. */
const KINDS: readonly (readonly [JudgmentTimingKind, BarTone])[] = [
  ['STATIC_REFUSAL', 'none'],
  ['BEFORE_RESPONSE', 'allow'],
  ['NEXT_REQUEST', 'stepup'],
  ['JUDGED_ALLOW', 'block'],
  ['OTHER', 'hold'],
];

const TRUTHS = ['THREAT', 'NORMAL', 'UNCERTAIN'] as const;
const EXPLANATIONS: readonly (readonly [string, BarTone])[] = [
  ['H1', 'allow'],
  ['H2', 'block'],
  ['H3', 'stepup'],
  ['H4', 'hold'],
  ['H5', 'link'],
  ['SEVERAL', 'brand'],
  ['NONE', 'none'],
];
const ACTION_ORDER = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'];

/**
 * 판정 품질 (옛 B-judgment · B-reasoning · B-prompt, DEC-51): how the attacks Contexa received ended, how long and what a
 * decision took; whether the AI's judgment can be trusted (the explanation the model judged most likely, its last
 * answer kept as it was, the reasons that match the facts, the questions asked again); and the published checks of the
 * text sent to the AI.
 */
export default function QualityTab({ view }: { readonly view: BenchmarkView }) {
  // The published prompt checks of the setting named in the address, the latest published record otherwise (as before).
  const asked = useValidationSetting();
  return (
    <div className={styles.stack}>
      <Outcomes view={view} />
      <Reasoning view={view} />
      <PromptChecks setting={asked} shown={view.spec?.settingHash ?? null} />
    </div>
  );
}

const VERDICT_KEYS: Readonly<Record<string, string>> = {
  ALLOW: 'ux.verdict.allow',
  CHALLENGE: 'ux.verdict.stepup',
  ESCALATE: 'ux.verdict.hold',
  BLOCK: 'ux.verdict.block',
};

/** An engine action in the decision's word, the action itself where it is none of the four. */
function useActionWord() {
  const { t } = useTranslation();
  return (action: string) => {
    const key = VERDICT_KEYS[action];
    return key ? t(key) : action;
  };
}

/** A run's steps in words: each decision with when it applied, and the steps answered without one of their own. */
function useStepWords() {
  const { t } = useTranslation();
  const actionWord = useActionWord();
  return (steps: readonly JudgmentStep[]) => {
    const words: string[] = [];
    for (let at = 0; at < steps.length; at++) {
      const step = steps[at] as JudgmentStep;
      if (step.action !== null) {
        const applied =
          step.applied === 'NEXT_REQUEST' && !step.applicable
            ? t('ux.validation.applied.late')
            : t(`ux.validation.applied.${step.applied}`, { defaultValue: step.applied });
        words.push(
          t('ux.validation.step.decided', { n: step.stepNo, verdict: actionWord(step.action), applied }),
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
      words.push(t(`ux.validation.step.${step.source}`, { n, defaultValue: `${n} ${step.source}` }));
    }
    return words.join(' · ');
  };
}

function Outcomes({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const n = (value: number) => formatNumber(value, i18n.language);
  const timing = view.judgmentTiming;
  const engine = view.engine;
  const others = judgmentOthers(view);
  const risk = riskKinds(view);
  const stepWords = useStepWords();
  const nameOf = (key: string) => view.cases.find((row) => row.key === key)?.title[language] ?? key;
  const segments: Segment[] = KINDS.filter(([kind]) => kind !== 'OTHER' || timing.OTHER > 0).map(
    ([kind, tone]) => ({
      label: t(`ux.validation.kind.end.${kind}`),
      value: timing[kind],
      tone,
    }),
  );
  const peak = Math.max(...(engine?.analysisBins ?? []).map((bin) => bin.decisions), 1);
  return (
    <>
      <Card
        title={t('ux.validation.outcome.title', { n: n(view.scope.attackRuns) })}
        sub={t('ux.validation.outcome.sub')}
      >
        <div className={styles.stack}>
          <StackedBar
            label={t('ux.validation.outcome.bar')}
            segments={segments}
            format={(value) => t('ux.validation.times', { n: n(value) })}
          />
          {others.length > 0 ? (
            <div className={styles.block}>
              <h3 className={styles.groupTitle}>
                {t('ux.validation.outcome.others', { n: n(timing.OTHER) })}
              </h3>
              <ul className={styles.notes}>
                {others.map((run) => (
                  <li key={run.runId}>
                    {t('ux.validation.outcome.other', {
                      name: nameOf(run.caseKey),
                      steps: stepWords(run.steps),
                      result: t(`ux.validation.result.${run.result}`, { defaultValue: run.result }),
                      items: n(run.exposedItems),
                    })}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          <ul className={styles.notes}>
            <li>{t('ux.validation.outcome.timing', { n: n(timing.NEXT_REQUEST) })}</li>
            <li>{t('ux.validation.outcome.judged', { n: n(timing.JUDGED_ALLOW) })}</li>
            <li>
              {risk
                ? t('ux.validation.outcome.riskKinds', {
                    runs: n(view.riskJudged.runs),
                    stopped: n(view.riskJudged.stopped),
                    kinds: KINDS.filter(([kind]) => (risk.kinds[kind] ?? 0) > 0)
                      .map(([kind]) => `${t(`ux.validation.kind.end.${kind}`)} ${n(risk.kinds[kind] ?? 0)}`)
                      .join(' · '),
                  })
                : t('ux.validation.outcome.risk', {
                    runs: n(view.riskJudged.runs),
                    stopped: n(view.riskJudged.stopped),
                  })}
            </li>
            {risk && risk.notStopped.length > 0 ? (
              <li>
                {t('ux.validation.outcome.notStopped', { cases: risk.notStopped.map(nameOf).join(' · ') })}
              </li>
            ) : null}
            {view.judgmentExposure
              ? KINDS.filter(([kind]) => (view.judgmentExposure?.[kind] ?? 0) > 0).map(([kind]) => (
                  <li key={kind}>
                    {t('ux.validation.outcome.exposed', {
                      kind: t(`ux.validation.kind.end.${kind}`),
                      items: n(view.judgmentExposure?.[kind] ?? 0),
                    })}
                  </li>
                ))
              : null}
          </ul>
        </div>
      </Card>
      <Card
        title={t('ux.validation.time.title', { n: n(engine?.analysisMeasured ?? 0) })}
        sub={engine ? t('ux.validation.time.sub') : undefined}
      >
        {!engine ? (
          // ST-57: no record of the engine.
          <p className={styles.note}>{t('ux.validation.time.none')}</p>
        ) : (
          <>
            {engine.analysisBins && engine.analysisBins.length > 0 ? (
              <ol className={styles.bins} aria-label={t('ux.validation.time.bins')}>
                {engine.analysisBins.map((bin) => (
                  <li key={bin.fromMs} className={styles.bin}>
                    <span className={styles.binLabel}>
                      {bin.toMs === null
                        ? t('ux.validation.time.binOpen', { from: formatSeconds(bin.fromMs, i18n.language) })
                        : t('ux.validation.time.bin', {
                            from: formatSeconds(bin.fromMs, i18n.language),
                            to: formatSeconds(bin.toMs, i18n.language),
                          })}
                    </span>
                    <span className={styles.binTrack} aria-hidden="true">
                      <span
                        className={styles.binBar}
                        style={{ inlineSize: `${(bin.decisions / peak) * 100}%` }}
                      />
                    </span>
                    <span className={styles.binValue}>
                      {t('ux.validation.decisionsN', { n: n(bin.decisions) })}
                    </span>
                  </li>
                ))}
              </ol>
            ) : null}
            <ul className={styles.notes}>
              <li>
                {t('ux.validation.time.times', {
                  p50:
                    engine.analysisP50Ms === null ? '—' : formatSeconds(engine.analysisP50Ms, i18n.language),
                  p95:
                    engine.analysisP95Ms === null ? '—' : formatSeconds(engine.analysisP95Ms, i18n.language),
                  n: n(engine.analysisMeasured),
                })}
              </li>
              {engine.costPerDecisionUsd !== null ? (
                <li>
                  {t('ux.validation.time.cost', {
                    usd: formatNumber(engine.costPerDecisionUsd, i18n.language, 4),
                    tokens: engine.tokensPerDecision === null ? '—' : n(Math.round(engine.tokensPerDecision)),
                    calls:
                      engine.modelCallsPerDecision === null
                        ? '—'
                        : formatNumber(engine.modelCallsPerDecision, i18n.language, 2),
                  })}
                </li>
              ) : null}
            </ul>
          </>
        )}
      </Card>
    </>
  );
}

function Reasoning({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const engine = view.engine;
  const reasoning = engine?.reasoning ?? null;
  const agreement = engine?.agreement ?? null;
  const reasons = useReasonMatch(view.spec?.settingHash ?? null);
  const actionWord = useActionWord();
  const threatLegitimate = reasoning?.mostLikely['THREAT']?.['H1'] ?? 0;
  const threatActions = reasoning ? (mostLikelyActions(reasoning)?.['THREAT']?.['H1'] ?? null) : null;
  return (
    <Card title={t('ux.validation.reasoning.title')} sub={t('ux.validation.reasoning.sub')}>
      {!engine ? (
        <p className={styles.note}>{t('ux.validation.time.none')}</p>
      ) : !reasoning ? (
        // ST-58: the record carries no count of the model's answers.
        <p className={styles.note}>{t('ux.validation.reasoning.none')}</p>
      ) : (
        <div className={styles.stack}>
          <p className={styles.line}>
            {t('ux.validation.reasoning.scope', { runs: n(view.scope.runs), decisions: n(engine.decisions) })}
          </p>
          <p className={styles.note}>{t('ux.validation.reasoning.read')}</p>
          {TRUTHS.filter((truth) => reasoning.mostLikely[truth] !== undefined).map((truth) => (
            <div key={truth} className={styles.block}>
              <h3 className={styles.groupTitle}>{t(`ux.validation.reasoning.truth.${truth}`)}</h3>
              <StackedBar
                label={t(`ux.validation.reasoning.truth.${truth}`)}
                segments={EXPLANATIONS.map(([id, tone]) => ({
                  label: t(`ux.validation.reasoning.explanation.${id}`),
                  value: reasoning.mostLikely[truth]?.[id] ?? 0,
                  tone,
                })).filter((segment) => segment.value > 0)}
                format={(value) => t('ux.validation.decisionsN', { n: n(value) })}
              />
            </div>
          ))}
          <ul className={styles.notes}>
            {threatLegitimate > 0 && threatActions ? (
              <li>
                {t('ux.validation.reasoning.h1Threat', {
                  n: n(threatLegitimate),
                  actions: Object.entries(threatActions)
                    .filter(([, decisions]) => decisions > 0)
                    .sort(([a], [b]) => ACTION_ORDER.indexOf(a) - ACTION_ORDER.indexOf(b))
                    .map(([action, decisions]) => `${actionWord(action)} ${n(decisions)}`)
                    .join(' · '),
                })}
              </li>
            ) : null}
            {agreement && agreement.modelAnswered > 0 ? (
              <li>
                {t('ux.validation.reasoning.agreement', {
                  as: n(agreement.asAnswered),
                  answered: n(agreement.modelAnswered),
                  technical: n(agreement.technical),
                  held: n(agreement.held),
                })}
              </li>
            ) : null}
            {reasons && reasons.total > 0 ? (
              <li>
                {t('ux.validation.reasoning.reasons', { hits: n(reasons.hits), total: n(reasons.total) })}
              </li>
            ) : null}
            <li>{t('ux.validation.reasoning.retried', { n: n(reasoning.retried) })}</li>
            {Object.entries(reasoning.flips).map(([flip, decisions]) => {
              const [from = flip, to = ''] = flip.split('->');
              return (
                <li key={flip}>
                  {t('ux.validation.reasoning.flip', {
                    from: actionWord(from),
                    to: actionWord(to),
                    n: n(decisions),
                  })}
                </li>
              );
            })}
          </ul>
          {reasoning.topRetryReasons.length > 0 ? (
            <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
              <table className={styles.table} data-stack>
                <caption className={styles.caption}>{t('ux.validation.reasoning.reasonsTitle')}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t('ux.validation.reasoning.reason')}</th>
                    <th scope="col">{t('ux.validation.reasoning.decisions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {reasoning.topRetryReasons.map((reason) => (
                    <tr key={reason.reason}>
                      <th scope="row">
                        <code className={styles.code} lang="en">
                          {breakable(reason.reason)}
                        </code>
                      </th>
                      <td data-k={t('ux.validation.reasoning.decisions')}>{n(reason.decisions)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      )}
    </Card>
  );
}

/** The seven published checks of the text sent to the AI, in the table's order. */
const CHECKS = [
  'delivery',
  'reaction',
  'invariance',
  'injection',
  'accuracy',
  'reasonMatch',
  'consistency',
] as const;
type CheckName = (typeof CHECKS)[number];

/** A bundle's version as a line names it ('2026.10.16-v20.24' is 'v20.24'). */
function shortBundle(bundle: string | null): string {
  return bundle ? bundle.slice(bundle.lastIndexOf('-') + 1) : '—';
}

/** The published checks of the text sent to the AI (옛 B-prompt): seven values, each with what it checks and its range. */
function PromptChecks({
  setting,
  shown,
}: {
  readonly setting: string | null;
  readonly shown: string | null;
}) {
  const { t, i18n } = useTranslation();
  const quality = usePromptQuality(setting);
  const view: PromptQualityView | null = quality.data ?? null;
  const counted = (rate: BenchmarkRate | null) => (rate ? rateCounts(rate, i18n.language) : '—');
  const rows: readonly {
    readonly name: CheckName;
    readonly value: string;
    readonly sample: string | null;
    readonly rate: BenchmarkRate;
  }[] = view
    ? [
        {
          name: 'delivery',
          value: rateCounts(view.delivery, i18n.language),
          sample: null,
          rate: view.delivery,
        },
        {
          name: 'reaction',
          value: ratePercent(view.reaction.direction.rate, i18n.language),
          sample: t('ux.validation.prompt.sample', { n: counted(view.reaction.direction) }),
          rate: view.reaction.direction,
        },
        {
          name: 'invariance',
          value: t('ux.validation.prompt.changes', {
            n: formatNumber(view.invariance.decisionChanges, i18n.language),
          }),
          sample: t('ux.validation.prompt.unchanged', { n: counted(view.invariance.firstStepFacts) }),
          rate: view.invariance.firstStepFacts,
        },
        {
          name: 'injection',
          value: t('ux.validation.prompt.injected', {
            n: formatNumber(view.injection.changed, i18n.language),
            total: formatNumber(view.injection.unchanged.total, i18n.language),
          }),
          sample: t('ux.validation.prompt.unchanged', { n: counted(view.injection.unchanged) }),
          rate: view.injection.unchanged,
        },
        ...(['accuracy', 'reasonMatch', 'consistency'] as const).map((name) => ({
          name,
          value: ratePercent(view[name].rate, i18n.language),
          sample: t('ux.validation.prompt.sample', { n: counted(view[name]) }),
          rate: view[name],
        })),
      ]
    : [];
  return (
    <>
      <Card
        title={t('ux.validation.prompt.title')}
        sub={
          view
            ? `${t('ux.validation.prompt.source', {
                date: formatUtc(view.measuredAt).slice(0, 10),
                setting: view.setting ? view.setting.slice(0, 12) : '—',
              })}${view.setting && shown && view.setting !== shown ? ` · ${t('ux.validation.prompt.otherSetting')}` : ''}`
            : undefined
        }
        flush
      >
        {quality.isPending ? (
          <Loading rows={4} />
        ) : quality.isError && notPublished(quality.error) ? (
          // ST-59: no published record yet.
          <p className={styles.padded}>{t('ux.validation.prompt.notMeasured')}</p>
        ) : !view ? (
          <ErrorState onRetry={() => void quality.refetch()}>{t('ux.validation.prompt.failed')}</ErrorState>
        ) : (
          <>
            <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
              <table className={styles.table} data-stack>
                <caption className="ux-sr-only">{t('ux.validation.prompt.title')}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t('ux.validation.prompt.col.name')}</th>
                    <th scope="col">{t('ux.validation.prompt.col.value')}</th>
                    <th scope="col">{t('ux.validation.prompt.col.what')}</th>
                    <th scope="col">{t('ux.validation.prompt.col.range')}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.name}>
                      <th scope="row">{t(`ux.validation.prompt.row.${row.name}`)}</th>
                      <td data-k={t('ux.validation.prompt.col.value')}>
                        <b>{row.value}</b>
                      </td>
                      <td data-k={t('ux.validation.prompt.col.what')}>
                        {t(`ux.validation.prompt.what.${row.name}`)}
                      </td>
                      <td data-k={t('ux.validation.prompt.col.range')}>
                        {row.sample ? <span className={styles.sub}>{row.sample}</span> : null}
                        <RateText rate={row.rate} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {view.comparison ? (
              <p className={styles.padded}>
                {t('ux.validation.prompt.comparison', {
                  before: shortBundle(view.comparison.baselineBundle),
                  now: shortBundle(view.comparison.bundle),
                  attackBefore: counted(view.comparison.attackBefore),
                  attackNow: counted(view.comparison.attackNow),
                  normalBefore: counted(view.comparison.normalBefore),
                  normalNow: counted(view.comparison.normalNow),
                })}
              </p>
            ) : null}
          </>
        )}
      </Card>
      {view ? <PromptMethod view={view} /> : null}
    </>
  );
}

/** How the prompt checks were made (옛 프롬프트 방법 창): what each value means, the values measured with them, the record and its raw data. */
function PromptMethod({ view }: { readonly view: PromptQualityView }) {
  const { t, i18n } = useTranslation();
  const extra: readonly (readonly [string, BenchmarkRate])[] = [
    ['minimumKept', view.reaction.minimumKept],
    ['reactionConsistency', view.reaction.consistency],
    ['decisions', view.invariance.decisions],
  ];
  const batches = view.batch ? [view.batch] : Object.values(view.batches ?? {});
  return (
    <Card title={t('ux.validation.promptMethod.title')}>
      <div className={styles.stack}>
        <ul className={styles.notes}>
          {CHECKS.map((name) => (
            <li key={name}>{t(`ux.validation.promptMethod.metric.${name}`)}</li>
          ))}
          <li>{t('ux.validation.method.interval')}</li>
        </ul>
        <div className={styles.block}>
          <h3 className={styles.groupTitle}>{t('ux.validation.promptMethod.extra')}</h3>
          <ul className={styles.notes}>
            {extra.map(([name, rate]) => (
              <li key={name}>
                {t(`ux.validation.promptMethod.${name}`, { value: rateCounts(rate, i18n.language) })} ·{' '}
                {ratePercent(rate.rate, i18n.language)}
              </li>
            ))}
          </ul>
        </div>
        <div className={styles.block}>
          <h3 className={styles.groupTitle}>{t('ux.validation.promptMethod.record')}</h3>
          <p className={styles.chips}>
            {batches.map((batch) => (
              <code key={batch} className={styles.code}>
                {breakable(batch)}
              </code>
            ))}
            <code className={styles.code}>{breakable(view.protocol ?? '—')}</code>
            <code className={styles.code}>{breakable((view.setting ?? '—').slice(0, 12))}</code>
            <span className={styles.sub}>
              {t('ux.validation.promptMethod.recordedAt', { date: formatUtc(view.measuredAt) })}
            </span>
          </p>
        </div>
        <div>
          <ButtonAnchor href={promptQualityRawHref(view.setting)} icon="download" size="sm">
            {t('ux.validation.promptMethod.raw')}
          </ButtonAnchor>
        </div>
      </div>
    </Card>
  );
}
