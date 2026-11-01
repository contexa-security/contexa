import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { benchmarkRunsHref, useAgentBenchmark, type BenchmarkView } from '../../../api/benchmark';
import { useBurstSnapshots } from '../../../api/agentSnapshots';
import { formatNumber, formatSeconds, formatUtc } from '../../format';
import { ButtonAnchor, Card, ErrorState, Field, Loading, Select } from '../../ui';
import { judgmentOthers, rateCounts, ratePercent, scoreOf, sentPerCase } from '../../validation/shapes';
import { RunDots } from './ValidationParts';
import styles from './Validation.module.css';
import { breakable } from '../../ui/breakable';

/**
 * 에이전트 (옛 B-agent, DEC-51): the operator's measured agent runs counted the way the person cases are, by the path a
 * request came by; the runs that differed between repeats, the bursts with and without decision merging, and the cases
 * Contexa also missed or could not measure under their current definition. A failed read says so (ST-61).
 */
export function AgentTab() {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const agent = useAgentBenchmark();
  const bursts = useBurstSnapshots();
  if (agent.isPending) {
    return <Loading rows={6} />;
  }
  if (!agent.data) {
    return <ErrorState onRetry={() => void agent.refetch()}>{t('ux.validation.agent.failed')}</ErrorState>;
  }
  const view = agent.data;
  const total = view.total;
  const build = view.build ?? null;
  const buildLine = build ? (
    <p className={styles.line}>
      {t('ux.validation.agent.build', {
        commit: build.codeCommit,
        engine: build.engineVersion,
        bundle: build.promptBundle ?? '—',
        mode: build.effectiveMode,
        setting: build.settingHash.slice(0, 12),
      })}
    </p>
  ) : null;
  if (view.scope.runs === 0 || !total) {
    return (
      <div className={styles.stack}>
        <p className={styles.line}>
          {t(build ? 'ux.validation.agent.emptyBuild' : 'build' in view ? 'ux.validation.agent.noBuild' : 'ux.validation.agent.empty')}
        </p>
        {buildLine}
      </div>
    );
  }
  const uncertain = view.uncertain ?? [];
  const columns = ['runs', 'attacks', 'existingMissed', 'contexaStopped', 'normals', 'falseBlocks'] as const;
  return (
    <div className={styles.stack}>
      <p className={styles.result}>
        {t('ux.validation.agent.result', {
          missed: n(total.existingMissed),
          stopped: n(total.contexaStopped),
          percent: ratePercent(total.contexaShare, i18n.language),
        })}
      </p>
      <p className={styles.line}>
        {t('ux.validation.agent.scope', {
          runs: n(view.scope.runs),
          cases: n(view.scope.cases),
          from: view.scope.from ? formatUtc(view.scope.from).slice(0, 10) : '—',
          to: view.scope.to ? formatUtc(view.scope.to).slice(0, 10) : '—',
        })}
      </p>
      {buildLine}
      <Card title={t('ux.validation.agent.paths')} sub={t('ux.validation.agent.source')} flush>
        <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
          <table className={styles.table} data-stack>
            <caption className="ux-sr-only">{t('ux.validation.agent.paths')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.validation.agent.col.path')}</th>
                {columns.map((column) => (
                  <th key={column} scope="col" data-numeric>
                    {t(`ux.validation.agent.col.${column}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[...view.byPath, { ...total, path: 'ALL' }].map((row) => (
                <tr key={row.path}>
                  <th scope="row">{t(`ux.validation.agent.path.${row.path}`, { defaultValue: row.path })}</th>
                  {columns.map((column) => (
                    <td key={column} data-numeric data-k={t(`ux.validation.agent.col.${column}`)}>
                      {n(row[column])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <ul className={styles.notes}>
        <li>
          {t('ux.validation.agent.falseBlocks', { blocked: n(total.falseBlocks), normals: n(total.normals) })}
        </li>
        <li>
          {t('ux.validation.agent.variation', {
            differing: n(view.variation.differing),
            cells: n(view.variation.cells),
          })}
        </li>
        {bursts.bursts.length > 0 ? (
          <li>
            {t('ux.validation.agent.bursts')}:{' '}
            {bursts.bursts
              .map((pair) =>
                t('ux.validation.agent.burstLine', {
                  requests: n(pair.on.summary.requests),
                  off: n(pair.off.summary.modelCalls),
                  on: n(pair.on.summary.modelCalls),
                }),
              )
              .join(' · ')}
          </li>
        ) : null}
        <li>
          {t('ux.validation.agent.missed', { n: n(view.contexaMissed.length) })}
          {view.contexaMissed.length > 0 ? ': ' : null}
          <KeyList keys={view.contexaMissed} />
        </li>
        <li>
          {t('ux.validation.agent.notMeasured', { n: n(view.notMeasured.length) })}
          {view.notMeasured.length > 0 ? ': ' : null}
          <KeyList keys={view.notMeasured} />
        </li>
        <li>
          {t('ux.validation.agent.uncertain', { n: n(uncertain.length) })}
          {uncertain.length > 0 ? ': ' : null}
          <KeyList keys={uncertain} />
        </li>
      </ul>
    </div>
  );
}

/**
 * 한계 (옛 B-limits): the scenarios Contexa got wrong, each with a dot per run and the reason the model wrote in its
 * latest wrong run, as written; Contexa's stop counts and what leaked; why the "stopped without a leak" count is low;
 * and the limits of the explanations of the bundle the setting ran.
 */
export function LimitsTab({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const n = (value: number) => formatNumber(value, i18n.language);
  const contexa = scoreOf(view.controls, 'D');
  const others = judgmentOthers(view);
  const nameOf = (key: string) => view.cases.find((row) => row.key === key)?.title[language] ?? key;
  const missedEvery = view.missedEveryRunCases ?? [];
  const wrong = (kind: 'THREAT' | 'NORMAL') => {
    const rows = view.cases.filter((row) => row.classification === kind && row.contexaWrong);
    return (
      <Card title={t(`ux.validation.limits.wrong.${kind}`)}>
        {rows.length === 0 ? (
          <p className={styles.note}>{t(`ux.validation.limits.none.${kind}`)}</p>
        ) : (
          <ul className={styles.wrongList}>
            {rows.map((row) => {
              const run =
                view.wrongRuns.find((candidate) => candidate.caseKey === row.key && candidate.reasoning) ??
                view.wrongRuns.find((candidate) => candidate.caseKey === row.key);
              return (
                <li key={row.key} className={styles.wrongCase}>
                  <span className={styles.pairName}>
                    {nameOf(row.key)} <span className={styles.sub}>{row.key}</span>
                  </span>
                  <RunDots
                    label={t('ux.validation.pair.dots', { name: nameOf(row.key) })}
                    runs={Object.entries(row.runResults ?? {}).map(([runId, results]) => ({
                      runId,
                      result: results.D ?? 'NOT_SCORED',
                    }))}
                  />
                  {run?.reasoning ? (
                    <p className={styles.para}>
                      <span className={styles.sub}>{t('ux.validation.limits.reason')} </span>
                      <q lang="en">{run.reasoning}</q>
                    </p>
                  ) : null}
                  {run ? (
                    <span className={styles.wrongRun}>
                      {kind === 'THREAT' ? (
                        <span>{t('ux.validation.limits.leaked', { items: n(run.exposedItems) })}</span>
                      ) : null}
                      <Link to={`/runs/${encodeURIComponent(run.runId)}`}>
                        {t('ux.validation.limits.openRun')}
                      </Link>
                    </span>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    );
  };
  if (!contexa) {
    return <p className={styles.line}>{t('ux.validation.empty')}</p>;
  }
  return (
    <div className={styles.stack}>
      <p className={styles.result}>
        {missedEvery.length > 0
          ? t('ux.validation.limits.missedEvery', {
              n: n(missedEvery.length),
              cases: missedEvery.map(nameOf).join(' · '),
            })
          : t('ux.validation.limits.missedNone')}
      </p>
      <div className={styles.split}>
        {wrong('THREAT')}
        {wrong('NORMAL')}
      </div>
      <Card title={t('ux.validation.limits.figures')}>
        <div className={styles.stack}>
          <dl className={styles.kv}>
            <div>
              <dt>{t('ux.validation.score.stopped')}</dt>
              <dd>{rateCounts(contexa.stopped, i18n.language)}</dd>
            </div>
            <div>
              <dt>{t('ux.validation.score.stoppedAny')}</dt>
              <dd>{rateCounts(contexa.stoppedAny, i18n.language)}</dd>
            </div>
            <div>
              <dt>{t('ux.validation.limits.exposed')}</dt>
              <dd>{t('ux.validation.items', { n: n(contexa.exposedItems) })}</dd>
            </div>
          </dl>
          <ul className={styles.notes}>
            {view.judgmentTiming.STATIC_REFUSAL > 0 ? (
              <li>{t('ux.validation.limits.static', { n: n(view.judgmentTiming.STATIC_REFUSAL) })}</li>
            ) : null}
            <li>
              {t('ux.validation.limits.why', {
                timing: n(view.judgmentTiming.NEXT_REQUEST),
                judged: n(view.judgmentTiming.JUDGED_ALLOW),
              })}
            </li>
            {others.length > 0 ? (
              <li>
                {t('ux.validation.limits.whyOthers', {
                  n: n(view.judgmentTiming.OTHER),
                  runs: others
                    .map(
                      (run) =>
                        `${nameOf(run.caseKey)}(${t(`ux.validation.result.${run.result}`, { defaultValue: run.result })})`,
                    )
                    .join(' · '),
                })}
              </li>
            ) : null}
          </ul>
        </div>
      </Card>
      <Card title={t('ux.validation.limits.explainTitle')}>
        <ul className={styles.notes}>
          {(view.spec?.promptBundles ?? []).some((bundle) => bundle.includes('-v21')) ? (
            <>
              <li>{t('ux.validation.limits.explain.retry')}</li>
              <li>{t('ux.validation.limits.explain.async')}</li>
            </>
          ) : (
            <>
              <li>{t('ux.validation.limits.explain.approval')}</li>
              <li>{t('ux.validation.limits.explain.inspector')}</li>
            </>
          )}
        </ul>
      </Card>
    </div>
  );
}

/**
 * 방법 (옛 방법 창, DEC-49): the measurement's range, the formulas, what is right and the ranges of variation, the
 * environment the runs were sent in with another setting to choose (`?setting=`), the time and the cost of a decision,
 * what visitors did (apart from the scores), the notices for a fair reading and the whole record to download.
 */
export function MethodTab({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const n = (value: number) => formatNumber(value, i18n.language);
  const spec = view.spec;
  const engine = view.engine;
  const observations = view.observations;
  const setting = params.get('setting');
  if (!spec) {
    return <p className={styles.line}>{t('ux.validation.empty')}</p>;
  }
  return (
    <div className={styles.stack}>
      <p className={styles.line}>
        {t('ux.validation.method.scope', {
          from: formatUtc(spec.firstRunAt),
          to: formatUtc(spec.lastRunAt),
          cases: n(view.scope.cases),
          runs: n(view.scope.runs),
          repeat: sentPerCase(view),
          unresolved: n(view.unresolvedRuns),
        })}
      </p>
      <div className={styles.split}>
        <Card title={t('ux.validation.method.formula')}>
          <ul className={styles.notes}>
            {(['stopped', 'stoppedAny', 'notBlocked', 'partial', 'unresolved'] as const).map((item) => (
              <li key={item}>{t(`ux.validation.method.formula.${item}`)}</li>
            ))}
          </ul>
        </Card>
        <Card title={t('ux.validation.method.truth')}>
          <ul className={styles.notes}>
            <li>{t('ux.validation.method.truthText')}</li>
            <li>{t('ux.validation.method.interval')}</li>
          </ul>
        </Card>
      </div>
      <div className={styles.split}>
        <Card title={t('ux.validation.method.environment')}>
          <div className={styles.stack}>
            <dl className={styles.kv}>
              <div>
                <dt>{t('ux.validation.method.period')}</dt>
                <dd>{`${formatUtc(spec.firstRunAt)} ~ ${formatUtc(spec.lastRunAt)} ${t('ux.runs.utc')}`}</dd>
              </div>
              <div>
                <dt>{t('ux.validation.method.model')}</dt>
                <dd>
                  <code className={styles.code}>{breakable(spec.chatModel)}</code>
                </dd>
              </div>
              <div>
                <dt>{t('ux.validation.method.setting')}</dt>
                <dd>
                  <code className={styles.code}>{breakable(spec.settingHash.slice(0, 12))}</code>
                </dd>
              </div>
              <div>
                <dt>{t('ux.validation.method.rules')}</dt>
                <dd>
                  <code className={styles.code}>{breakable(spec.ruleVersion.slice(0, 12))}</code>
                </dd>
              </div>
              <div>
                <dt>{t('ux.validation.method.code')}</dt>
                <dd>
                  <code className={styles.code}>
                    {breakable(`${spec.codeCommit} · ${spec.engineVersion}`)}
                  </code>
                </dd>
              </div>
              <div>
                <dt>{t('ux.validation.method.protocol')}</dt>
                <dd>
                  {view.scope.protocols.map((protocol) => (
                    <code key={protocol.protocolId} className={styles.code}>
                      {breakable(protocol.protocolId)}
                    </code>
                  ))}
                </dd>
              </div>
            </dl>
            {view.specs.length > 1 ? (
              <Field label={t('ux.validation.method.settingLabel')}>
                {(props) => (
                  <Select
                    {...props}
                    compact
                    value={spec.settingHash}
                    onChange={(event) => {
                      const next = new URLSearchParams(params);
                      // The latest setting is the default: it leaves the address without a setting.
                      if (event.target.value === view.specs[0]?.settingHash) {
                        next.delete('setting');
                      } else {
                        next.set('setting', event.target.value);
                      }
                      setParams(next, { replace: true });
                    }}
                  >
                    {view.specs.map((candidate, index) => (
                      <option key={candidate.settingHash} value={candidate.settingHash}>
                        {t(
                          index === 0
                            ? 'ux.validation.method.settingLatest'
                            : 'ux.validation.method.settingOption',
                          {
                            from: formatUtc(candidate.firstRunAt),
                            runs: n(candidate.protocolRuns),
                          },
                        )}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            ) : null}
          </div>
        </Card>
        <Card title={t('ux.validation.method.ops')}>
          {engine ? (
            <dl className={styles.kv}>
              <div>
                <dt>{t('ux.validation.method.time')}</dt>
                <dd>
                  {engine.analysisP50Ms === null
                    ? '—'
                    : t('ux.time.seconds', { value: formatSeconds(engine.analysisP50Ms, i18n.language) })}
                </dd>
              </div>
              <div>
                <dt>{t('ux.validation.method.cost')}</dt>
                <dd>
                  {engine.costPerDecisionUsd === null
                    ? '—'
                    : `$${formatNumber(engine.costPerDecisionUsd, i18n.language, 4)}`}
                </dd>
              </div>
              <div>
                <dt>{t('ux.validation.method.decisions')}</dt>
                <dd>{n(engine.decisions)}</dd>
              </div>
              <div>
                <dt>{t('ux.validation.method.detail')}</dt>
                <dd>
                  {t('ux.validation.method.detailValue', {
                    p95:
                      engine.analysisP95Ms === null
                        ? '—'
                        : formatSeconds(engine.analysisP95Ms, i18n.language),
                    tokens: engine.tokensPerDecision === null ? '—' : n(Math.round(engine.tokensPerDecision)),
                    calls:
                      engine.modelCallsPerDecision === null
                        ? '—'
                        : formatNumber(engine.modelCallsPerDecision, i18n.language, 1),
                  })}
                </dd>
              </div>
              {engine.priceSource ? (
                <div>
                  <dt>{t('ux.validation.method.price')}</dt>
                  <dd>
                    <code className={styles.code}>{breakable(engine.priceSource)}</code>
                  </dd>
                </div>
              ) : null}
            </dl>
          ) : (
            <p className={styles.note}>{t('ux.validation.time.none')}</p>
          )}
        </Card>
      </div>
      <div className={styles.split}>
        <Card title={t('ux.validation.method.visitors')}>
          <ul className={styles.notes}>
            <li>
              {t('ux.validation.method.visitorRuns', {
                live: n(observations.liveRuns),
                lab: n(observations.labRuns),
              })}
            </li>
            <li>
              {t('ux.validation.method.predictions', {
                hits: n(observations.predictions.hits),
                total: n(observations.predictions.total),
                rate: ratePercent(observations.predictions.rate, i18n.language),
              })}
            </li>
            <li>
              {t('ux.validation.method.assessments', {
                n: n(observations.assessments),
                people: n(observations.assessors),
              })}
            </li>
            <li>{t('ux.validation.method.apart')}</li>
          </ul>
        </Card>
        <Card title={t('ux.validation.method.notices')}>
          <ul className={styles.notes}>
            {view.notices.map((notice) => (
              <li key={notice}>{t(`ux.validation.notice.${notice}`, { defaultValue: notice })}</li>
            ))}
          </ul>
        </Card>
      </div>
      <div>
        <ButtonAnchor href={benchmarkRunsHref(setting)} icon="download">
          {t('ux.validation.method.raw')}
        </ButtonAnchor>
      </div>
    </div>
  );
}

/** Case keys separated by commas, a line breaking only between two keys. */
function KeyList({ keys }: { readonly keys: readonly string[] }) {
  return (
    <>
      {keys.map((key, index) => (
        <span key={key}>
          <span className={styles.piece}>{index < keys.length - 1 ? `${key},` : key}</span>
          {index < keys.length - 1 ? ' ' : null}
        </span>
      ))}
    </>
  );
}
