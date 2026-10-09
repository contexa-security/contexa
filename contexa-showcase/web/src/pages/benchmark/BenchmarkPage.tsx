import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import {
  useBenchmark,
  type BenchmarkCase,
  type BenchmarkRate,
  type BenchmarkView,
  type ControlScore,
} from '../../api/benchmark';
import { useCases } from '../../api/anatomy';
import { AppHeader } from '../../components/AppHeader';
import { ActionChip } from '../../components/common/ActionChip';
import { useDetail } from '../../components/detail/useDetail';
import { StateScreen } from '../../components/StateScreen';
import { VerdictChip } from '../../components/VerdictChip';
import { CONTROL_ORDER, type ControlId, type Verdict } from '../../domain/verdict';
import styles from './BenchmarkPage.module.css';

/*
 * The benchmark (docs/showcase/데모-재설계.md 5A.2, the W3 draft as approved): the five approaches measured on the same
 * designed cases under one measurement setting. Every number is the portal's (/api/benchmark), counted from the stored
 * protocol runs by the one scoring rule; the page draws and words them, and judges nothing itself.
 */
const KNOWN_VERDICTS = new Set(['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK']);
const SETTING = /^[0-9a-f]{64}$/;

function percent(value: number | null): string {
  return value === null ? '-' : `${Math.round(value * 1000) / 10}%`;
}

function rateArgs(rate: BenchmarkRate) {
  return {
    rate: percent(rate.rate),
    successes: rate.hits,
    total: rate.total,
    low: percent(rate.low),
    high: percent(rate.high),
  };
}

/** Pairs first (an attack next to the legitimate case that looks the same), then single attacks, normal, open. */
function ordered(cases: readonly BenchmarkCase[]): BenchmarkCase[] {
  const keys = new Set(cases.map((row) => row.key));
  const pairKey = (key: string) => (key.endsWith('T') && keys.has(key.slice(0, -1)) ? key.slice(0, -1) : key);
  const group = (row: BenchmarkCase) => {
    if (keys.has(`${row.key}T`) || (row.key.endsWith('T') && keys.has(row.key.slice(0, -1)))) {
      return 0;
    }
    return row.classification === 'THREAT' ? 1 : row.classification === 'NORMAL' ? 2 : 3;
  };
  return [...cases].sort(
    (a, b) =>
      group(a) - group(b) || pairKey(a.key).localeCompare(pairKey(b.key)) || a.key.localeCompare(b.key),
  );
}

export default function BenchmarkPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const requested = params.get('setting');
  const setting = requested && SETTING.test(requested) ? requested : null;
  const benchmark = useBenchmark(setting);
  return (
    <>
      <AppHeader />
      <main id="main" className={styles.page}>
        <h1 className={styles.title}>{t('bench.title')}</h1>
        {benchmark.data ? (
          <Benchmark
            view={benchmark.data}
            onSetting={(next) => setParams(next ? { setting: next } : {}, { replace: true })}
          />
        ) : benchmark.isError ? (
          <StateScreen kind="error" onRetry={() => void benchmark.refetch()} />
        ) : (
          <p>{t('anatomy.loading')}</p>
        )}
      </main>
    </>
  );
}

function Benchmark({
  view,
  onSetting,
}: {
  readonly view: BenchmarkView;
  readonly onSetting: (setting: string | null) => void;
}) {
  const { t } = useTranslation();
  if (!view.spec) {
    return <p className={styles.note}>{t('bench.empty')}</p>;
  }
  return (
    <>
      <section className={styles.notices} aria-labelledby="notices-title">
        <h2 id="notices-title" className={styles.sectionTitle}>
          {t('bench.notices.title')}
        </h2>
        <ul className={styles.method}>
          {view.notices.map((notice) => (
            <li key={notice}>{t(`bench.notice.${notice}`)}</li>
          ))}
        </ul>
      </section>
      <ScopeSection view={view} onSetting={onSetting} />
      <CardSection controls={view.controls} />
      <MatrixSection cases={view.cases} />
      <WrongSection view={view} />
      <VisitorsSection view={view} />
      <OpsSection view={view} />
      <section className={styles.section} aria-labelledby="method-title">
        <h2 id="method-title" className={styles.sectionTitle}>
          {t('bench.method.title')}
        </h2>
        <ul className={styles.method}>
          {(
            [
              'detection',
              'falseBlock',
              'partial',
              'unresolved',
              'interval',
              'macro',
              'truth',
              'setting',
              'composed',
            ] as const
          ).map((item) => (
            <li key={item}>{t(`bench.method.${item}`)}</li>
          ))}
        </ul>
      </section>
    </>
  );
}

/** The scope first (5A.2 1): the cases, the runs, the protocols, the setting and the frozen rules. */
function ScopeSection({
  view,
  onSetting,
}: {
  readonly view: BenchmarkView;
  readonly onSetting: (setting: string | null) => void;
}) {
  const { t } = useTranslation();
  const catalog = useCases();
  const spec = view.spec;
  if (!spec) {
    return null;
  }
  const kinds = { THREAT: 0, NORMAL: 0, UNCERTAIN: 0 } as Record<string, number>;
  for (const row of catalog.data?.cases ?? []) {
    kinds[row.classification] = (kinds[row.classification] ?? 0) + 1;
  }
  const layer1 = (spec.modelSettings?.['layer1Model'] ?? null) as Record<string, unknown> | null;
  return (
    <section className={styles.section} aria-labelledby="scope-title">
      <h2 id="scope-title" className={styles.sectionTitle}>
        {t('bench.scope.title')}
      </h2>
      {view.specs.length > 1 ? (
        <label className={styles.field}>
          <span className={styles.fieldName}>{t('bench.scope.settingChoice')}</span>
          <select
            className={styles.select}
            value={spec.settingHash}
            onChange={(event) =>
              onSetting(event.target.value === view.specs[0]?.settingHash ? null : event.target.value)
            }
          >
            {view.specs.map((candidate, index) => (
              <option key={candidate.settingHash} value={candidate.settingHash}>
                {t(index === 0 ? 'bench.scope.settingLatest' : 'bench.scope.settingOption', {
                  hash: candidate.settingHash.slice(0, 12),
                  model: candidate.chatModel,
                  from: candidate.firstRunAt.slice(0, 16).replace('T', ' '),
                  runs: candidate.protocolRuns,
                })}
              </option>
            ))}
          </select>
        </label>
      ) : null}
      <dl className={styles.numbers}>
        <div>
          <dt>{t('bench.scope.cases')}</dt>
          <dd>
            {t('bench.scope.casesValue', {
              total: catalog.data?.cases.length ?? '-',
              threat: kinds['THREAT'] ?? 0,
              normal: kinds['NORMAL'] ?? 0,
              uncertain: kinds['UNCERTAIN'] ?? 0,
            })}
          </dd>
        </div>
        <div>
          <dt>{t('bench.scope.runs')}</dt>
          <dd>
            {t('bench.scope.measuredValue', {
              runs: view.scope.runs,
              attack: view.scope.attackRuns,
              normal: view.scope.normalRuns,
              other: view.scope.otherRuns,
              cases: view.scope.cases,
            })}
          </dd>
        </div>
        <div>
          <dt>{t('bench.scope.period')}</dt>
          <dd className={styles.mono}>
            {spec.firstRunAt.slice(0, 16).replace('T', ' ')} → {spec.lastRunAt.slice(0, 16).replace('T', ' ')}
          </dd>
        </div>
      </dl>
      <ul className={styles.specs}>
        {view.scope.protocols.map((protocol) => (
          <li key={protocol.protocolId} className={styles.mono}>
            {t('bench.scope.protocol', {
              id: protocol.protocolId,
              repeat: protocol.repeat,
              cases: protocol.cases,
              planned: protocol.plannedRuns,
              completed: protocol.completedRuns,
              failed: protocol.failedRuns,
              forced: protocol.forcedRuns,
            })}
          </li>
        ))}
        <li className={styles.mono}>
          {t('bench.scope.setting', {
            hash: spec.settingHash.slice(0, 12),
            model: spec.chatModel,
            effort: String(layer1?.['reasoningEffort'] ?? '-'),
            tokens: String(layer1?.['maxOutputTokens'] ?? '-'),
            rules: spec.ruleVersion.slice(0, 12),
            commit: spec.codeCommit,
          })}
        </li>
        <li className={styles.mono}>
          {t('bench.scope.templates', {
            templates: spec.templates.join(', ') || '-',
            version: spec.templateVersions.map((version) => version.slice(0, 12)).join(', ') || '-',
          })}
        </li>
      </ul>
      {view.protocolRunsWithoutSetting > 0 ? (
        <p className={styles.note}>
          {t('bench.scope.withoutSetting', { n: view.protocolRunsWithoutSetting })}
        </p>
      ) : null}
      {catalog.data ? (
        <p className={styles.note}>
          {t('bench.scope.frozen', {
            rules: catalog.data.rules.sha256?.slice(0, 12) ?? '-',
          })}
        </p>
      ) : null}
      <p className={styles.warning}>
        {t('bench.scope.small', {
          repeat: view.scope.protocols.map((protocol) => protocol.repeat).join(', '),
        })}
      </p>
    </section>
  );
}

function CardSection({ controls }: { readonly controls: readonly ControlScore[] }) {
  const { t } = useTranslation();
  return (
    <section className={styles.section} aria-labelledby="card-title">
      <h2 id="card-title" className={styles.sectionTitle}>
        {t('bench.card.title')}
      </h2>
      <p className={styles.note}>{t('bench.card.lead')}</p>
      <ol className={styles.card}>
        {controls.map((row) => (
          <li key={row.control} className={styles.cardRow} data-contexa={row.control === 'D' || undefined}>
            <span className={styles.cardName}>{t(`control.${row.control}.name`)}</span>
            <Bar
              label={t('bench.card.detection')}
              rate={row.stoppedAny}
              kind="detection"
              detail={t('bench.card.threatDetail', {
                stopped: row.stopped.hits,
                partly: row.stoppedAny.hits - row.stopped.hits,
                missed: row.stoppedAny.total - row.stoppedAny.hits,
                unresolved: row.attackUnresolved,
                exposed: row.exposedItems.toLocaleString(),
                macro: percent(row.stoppedAnyMacro),
              })}
            />
            <Bar
              label={t('bench.card.falseBlock')}
              rate={row.falseBlock}
              kind="falseBlock"
              detail={t('bench.card.normalDetail', {
                passed: row.falseBlock.total - row.falseBlock.hits - row.friction.hits,
                checked: row.friction.hits,
                halted: row.falseBlock.hits,
                unresolved: row.normalUnresolved,
                macro: percent(row.falseBlockMacro),
              })}
            />
          </li>
        ))}
      </ol>
    </section>
  );
}

/** A rate as a bar with its sample size and its 95% interval drawn on the same scale. */
function Bar({
  label,
  rate,
  kind,
  detail,
}: {
  readonly label: string;
  readonly rate: BenchmarkRate;
  readonly kind: 'detection' | 'falseBlock';
  readonly detail: string;
}) {
  const { t } = useTranslation();
  const value = rate.rate ?? 0;
  return (
    <div className={styles.bar}>
      <span className={styles.barLabel}>{label}</span>
      <span className={styles.barTrack} role="img" aria-label={t('bench.rateWithInterval', rateArgs(rate))}>
        <span
          className={styles.barInterval}
          style={{
            insetInlineStart: `${(rate.low ?? 0) * 100}%`,
            inlineSize: `${((rate.high ?? 0) - (rate.low ?? 0)) * 100}%`,
          }}
        />
        <span className={styles.barFill} data-kind={kind} style={{ inlineSize: `${value * 100}%` }} />
      </span>
      <span className={styles.barValue}>{t('bench.rateWithInterval', rateArgs(rate))}</span>
      <span className={styles.note}>{detail}</span>
    </div>
  );
}

function MatrixSection({ cases }: { readonly cases: readonly BenchmarkCase[] }) {
  const { t, i18n } = useTranslation();
  const detail = useDetail();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  return (
    <section className={styles.section} aria-labelledby="matrix-title">
      <h2 id="matrix-title" className={styles.sectionTitle}>
        {t('bench.matrix.title')}
      </h2>
      <p className={styles.note}>{t('bench.matrix.lead')}</p>
      <div className={styles.tableWrap} tabIndex={0} role="region" aria-labelledby="matrix-title">
        <table className={styles.matrix}>
          <thead>
            <tr>
              <th scope="col">{t('bench.matrix.case')}</th>
              {CONTROL_ORDER.map((control) => (
                <th key={control} scope="col">
                  {t(`control.${control}.name`)}
                </th>
              ))}
              <th scope="col">{t('bench.matrix.engine')}</th>
            </tr>
          </thead>
          <tbody>
            {ordered(cases).map((row) => (
              <tr key={row.key}>
                <th scope="row" className={styles.caseCell}>
                  <span className={styles.caseKey}>{row.key}</span>
                  <span className={styles.caseTitle}>{row.title[language] ?? ''}</span>
                  <span className={styles.truth} data-classification={row.classification}>
                    {t(`anatomy.class.${row.classification}`)}
                  </span>
                </th>
                {CONTROL_ORDER.map((control) => (
                  <MatrixValue key={control} row={row} control={control} />
                ))}
                <td className={styles.engineCell}>
                  <span>
                    {Object.entries(row.engineActions).length === 0
                      ? t('bench.matrix.noDecision')
                      : Object.entries(row.engineActions)
                          .map(([action, count]) => `${action} ${count}`)
                          .join(' · ')}
                  </span>
                  <span className={styles.mono}>
                    {row.risk.scored === 0
                      ? t('bench.matrix.noRisk', { decisions: row.risk.decisions })
                      : t('bench.matrix.risk', {
                          min: row.risk.min?.toFixed(2) ?? '-',
                          max: row.risk.max?.toFixed(2) ?? '-',
                          scored: row.risk.scored,
                          decisions: row.risk.decisions,
                        })}
                  </span>
                  <details className={styles.runs}>
                    <summary>{t('bench.matrix.runs', { n: row.runIds.length })}</summary>
                    <ol className={styles.runList}>
                      {row.runIds.map((runId) => (
                        <li key={runId}>
                          <ActionChip
                            onClick={() => detail.show(runId)}
                            icon="search"
                            variant="open"
                            size="sm"
                          >
                            {runId}
                          </ActionChip>
                        </li>
                      ))}
                    </ol>
                  </details>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/** A cell as the portal counted it: runs handled as the ground truth says over the scored runs. */
function MatrixValue({ row, control }: { readonly row: BenchmarkCase; readonly control: ControlId }) {
  const { t } = useTranslation();
  const cell = row.cells[control];
  if (!cell) {
    return <td className={styles.valueCell}>{t('bench.matrix.notScored')}</td>;
  }
  const state =
    cell.counted === 0
      ? 'none'
      : cell.right === cell.counted
        ? 'right'
        : cell.right === 0
          ? 'wrong'
          : 'mixed';
  return (
    <td className={styles.valueCell} data-state={state} data-classification={row.classification}>
      {t('bench.matrix.value', { good: cell.right, counted: cell.counted })}
    </td>
  );
}

function WrongSection({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const detail = useDetail();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const titles = new Map(view.cases.map((row) => [row.key, row.title[language] ?? '']));
  return (
    <section className={styles.section} aria-labelledby="wrong-title">
      <h2 id="wrong-title" className={styles.sectionTitle}>
        {t('bench.wrong.title', { n: view.wrongRunCount })}
      </h2>
      <p className={styles.note}>{t('bench.wrong.lead', { unresolved: view.unresolvedRuns })}</p>
      <ol className={styles.wrongList}>
        {view.wrongRuns.map((wrong) => (
          <li key={wrong.runId} className={styles.wrong}>
            <div className={styles.wrongHead}>
              <span className={styles.caseKey}>{wrong.caseKey}</span>
              <span>{titles.get(wrong.caseKey) ?? ''}</span>
              <span className={styles.truth} data-classification={wrong.classification}>
                {t(`anatomy.class.${wrong.classification}`)}
              </span>
              <span className={styles.wrongResult}>
                {t(`score.result.${wrong.result}`, { n: wrong.exposedItems, count: wrong.exposedItems })}
              </span>
            </div>
            <div className={styles.wrongBody}>
              <VerdictChip
                verdict={
                  (wrong.finalAction && KNOWN_VERDICTS.has(wrong.finalAction)
                    ? wrong.finalAction
                    : 'NONE') as Verdict
                }
                unresolved={wrong.result === 'UNRESOLVED'}
                showCode
              />
              <span className={styles.mono}>
                {wrong.riskScore === null
                  ? t('bench.wrong.noRisk')
                  : t('bench.wrong.risk', { risk: wrong.riskScore.toFixed(2) })}
              </span>
              <span className={styles.mono}>
                {wrong.coreAdverseMet === null
                  ? t('bench.wrong.signalsNone')
                  : t('bench.wrong.signals', { n: wrong.coreAdverseMet })}
              </span>
            </div>
            <p className={styles.reasoning}>{wrong.reasoning ?? '-'}</p>
            {wrong.stepNo !== null ? (
              <ActionChip
                onClick={() => detail.show(wrong.runId, wrong.stepNo ?? 1)}
                icon="search"
                variant="open"
                size="sm"
              >
                {t('bench.wrong.open', { step: wrong.stepNo })}
              </ActionChip>
            ) : null}
          </li>
        ))}
      </ol>
    </section>
  );
}

/** Visitors' calls and opinions, set apart from the measurement (R-26): unchecked expertise, counted after a delay. */
function VisitorsSection({ view }: { readonly view: BenchmarkView }) {
  const { t } = useTranslation();
  const observed = view.observations;
  return (
    <section className={styles.visitors} aria-labelledby="visitors-title">
      <h2 id="visitors-title" className={styles.sectionTitle}>
        {t('bench.visitors.title')}
      </h2>
      <p className={styles.note}>{t('bench.visitors.apart')}</p>
      <dl className={styles.numbers}>
        <div>
          <dt>{t('bench.visitors.runs')}</dt>
          <dd>
            {t('bench.visitors.runsValue', {
              live: observed.liveRuns,
              lab: observed.labRuns,
              composed: observed.composedRuns,
            })}
          </dd>
        </div>
        <div>
          <dt>{t('bench.visitors.predictions')}</dt>
          <dd>
            {t('bench.visitors.predictionsValue', {
              all: observed.predictionsAll,
              designed: observed.predictions.total + observed.unsurePredictions,
              unsure: observed.unsurePredictions,
            })}
          </dd>
        </div>
        <div>
          <dt>{t('bench.visitors.accuracy')}</dt>
          <dd>{t('bench.rateWithInterval', rateArgs(observed.predictions))}</dd>
        </div>
        <div>
          <dt>{t('bench.visitors.assessments')}</dt>
          <dd>
            {t('bench.visitors.assessmentsValue', {
              all: observed.assessments,
              visitors: observed.assessors,
              sound: percent(observed.soundShareWeighted),
            })}
          </dd>
        </div>
      </dl>
      {Object.keys(observed.reasons).length > 0 ? (
        <ul className={styles.method}>
          {Object.entries(observed.reasons).map(([reason, count]) => (
            <li key={reason}>
              {t(`lab.reason.${reason}`)} · {count}
            </li>
          ))}
        </ul>
      ) : null}
      <p className={styles.note}>{t('bench.visitors.rule', { hours: observed.delayHours })}</p>
    </section>
  );
}

function OpsSection({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const engine = view.engine;
  if (!engine) {
    return null;
  }
  const format = (value: number) => value.toLocaleString(i18n.language);
  return (
    <section className={styles.section} aria-labelledby="ops-title">
      <h2 id="ops-title" className={styles.sectionTitle}>
        {t('bench.ops.title')}
      </h2>
      <dl className={styles.numbers}>
        <div>
          <dt>{t('bench.ops.decisions')}</dt>
          <dd>
            {t('bench.ops.decisionsValue', {
              n: engine.decisions,
              actions:
                Object.entries(engine.actions)
                  .map(([action, count]) => `${action} ${count}`)
                  .join(' · ') || '-',
            })}
          </dd>
        </div>
        <div>
          <dt>{t('bench.ops.analysis')}</dt>
          <dd className={styles.mono}>
            {t('bench.ops.analysisValue', {
              p50: engine.analysisP50Ms === null ? '-' : format(engine.analysisP50Ms),
              p95: engine.analysisP95Ms === null ? '-' : format(engine.analysisP95Ms),
              n: engine.analysisMeasured,
            })}
          </dd>
        </div>
        <div>
          <dt>{t('bench.ops.unresolved')}</dt>
          <dd>{t('bench.ops.unresolvedValue', { n: engine.unresolved, of: engine.decisions })}</dd>
        </div>
        <div>
          <dt>{t('bench.ops.tokens')}</dt>
          <dd className={styles.mono}>
            {t('bench.ops.tokensValue', {
              tokens: engine.tokensPerDecision === null ? '-' : format(Math.round(engine.tokensPerDecision)),
              calls: engine.modelCallsPerDecision === null ? '-' : engine.modelCallsPerDecision.toFixed(2),
            })}
          </dd>
        </div>
        <div>
          <dt>{t('bench.ops.cost')}</dt>
          <dd className={styles.mono}>
            {engine.costPerDecisionUsd === null
              ? t('bench.ops.costNone')
              : t('bench.ops.costValue', { usd: engine.costPerDecisionUsd.toFixed(6) })}
          </dd>
        </div>
      </dl>
      <p className={styles.note}>
        {t('bench.ops.tokenTotals', {
          prompt: format(engine.promptTokens),
          cached: format(engine.cachedTokens),
          completion: format(engine.completionTokens),
          calls: engine.modelCalls,
        })}
      </p>
      {engine.priceSource ? (
        <p className={styles.note}>{t('bench.ops.priceSource', { source: engine.priceSource })}</p>
      ) : null}
    </section>
  );
}
