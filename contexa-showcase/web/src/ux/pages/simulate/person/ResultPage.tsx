import { useTranslation } from 'react-i18next';
import { Navigate, useParams, useSearchParams } from 'react-router-dom';
import { useAnatomy } from '../../../../api/anatomy';
import { useStepResult, useLabOptions } from '../../../../api/lab';
import { useRunScore, useStats } from '../../../../api/queries';
import { useStepResponses } from '../../../../api/responses';
import type { RunScore } from '../../../../api/types';
import { CONTROL_ORDER } from '../../../../domain/verdict';
import { formatDuration, formatNumber, formatUtc } from '../../../format';
import { CONTROL_TONE } from '../../../simulate/controls';
import { CompareView } from '../../../simulate/CompareView';
import { Evidence } from '../../../simulate/Evidence';
import { FlowProgress, FlowSteps } from '../../../simulate/FlowFrame';
import { StoredCheckRecord } from '../../../simulate/Recovery';
import {
  EXISTING,
  conclusionKey,
  evalOf,
  flowPath,
  personCase,
  type PersonCase,
  type PersonKey,
  decidingStep,
  verdictOf,
} from '../../../simulate/person';
import { usePersonRuns } from '../../../simulate/useFlow';
import { UX_VERDICTS } from '../../../verdict';
import {
  Badge,
  Bar,
  ButtonLink,
  CodeChip,
  EvalBadge,
  Icon,
  Loading,
  Note,
  PageHead,
  TabPanel,
  Tabs,
  VerdictBadge,
} from '../../../ui';
import styles from '../../../simulate/Result.module.css';

/**
 * Step 4 (기획안 7.0 d-result, F-6): the conclusion in one sentence, the exported items of the five controls side by
 * side, the decision time and how it applied, the evidence the engine cited and the three next checks. When both runs
 * of the shared request exist, the comparison "same request, different decision" opens as a tab (F-7). Every sentence is
 * picked from the server's score of the run (/api/runs/{id}/score); the screen never judges the run itself.
 */
export default function ResultPage() {
  const { caseKey } = useParams();
  const scenario = personCase(caseKey);
  if (!scenario) {
    return <Navigate replace to="/simulate/person" />;
  }
  return <Result scenario={scenario} />;
}

function Result({ scenario }: { readonly scenario: PersonCase }) {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const runs = usePersonRuns();
  const key = scenario.key;
  const asked = params.get('run');
  const runOf = (of: PersonKey) => (of === key && asked ? asked : (runs.latest(of)?.runId ?? null));
  const pairKey = scenario.pair;
  const both = pairKey !== null && runOf(key) !== null && runOf(pairKey) !== null;
  const order: readonly PersonKey[] = pairKey ? (key === 'S13' ? [key, pairKey] : [pairKey, key]) : [key];
  const tab = params.get('tab') ?? key;
  const current = both && (tab === 'compare' || order.includes(tab as PersonKey)) ? tab : key;
  const select = (id: string) => {
    const next = new URLSearchParams(params);
    next.set('tab', id);
    setParams(next, { replace: true });
  };

  if (!runs.ready && !asked) {
    return (
      <>
        <FlowSteps current="result" />
        <Loading rows={6} />
      </>
    );
  }
  const runId = runOf(key);
  if (runId === null) {
    return (
      <>
        <FlowSteps current="result" />
        {/* A visitor without a run of the scenario still lands on a titled screen (기획안 11절 2-3). */}
        <PageHead title={t('ux.result.title')} />
        <Note>{t('ux.result.none')}</Note>
        <ButtonLink to={flowPath(key, 'review')} variant="primary" iconAfter="arrow-right">
          {t('ux.live.toReview')}
        </ButtonLink>
      </>
    );
  }
  return (
    <>
      <FlowSteps current="result" />
      {both ? (
        <>
          <Tabs
            idBase="result"
            label={t('ux.result.tabs')}
            value={current}
            onChange={select}
            items={[
              ...order.map((of) => ({ id: of, label: t('ux.result.tab', { key: of }) })),
              { id: 'compare', label: t('ux.compare.title') },
            ]}
          />
          <TabPanel idBase="result" id={current}>
            {current === 'compare' ? (
              <CompareView attackerRun={runOf('S13') ?? ''} ownerRun={runOf('S13T') ?? ''} />
            ) : (
              <RunResult caseKey={current as PersonKey} runId={runOf(current as PersonKey) ?? runId} />
            )}
          </TabPanel>
        </>
      ) : (
        <RunResult caseKey={key} runId={runId} />
      )}
      <FlowProgress />
    </>
  );
}

function RunResult({ caseKey, runId }: { readonly caseKey: PersonKey; readonly runId: string }) {
  const { t, i18n } = useTranslation();
  const scenario = personCase(caseKey) as PersonCase;
  const options = useLabOptions();
  const labCase = options.data?.cases.find((candidate) => candidate.key === caseKey) ?? null;
  const steps = labCase?.steps ?? 1;
  const score = useRunScore(runId, 'result', steps);
  // The request the result rests on (a case of several requests may decide at its second or third).
  const step = score.data ? decidingStep(score.data) : 1;
  const result = useStepResult(runId, step);
  const anatomy = useAnatomy(runId, step);
  const runs = usePersonRuns();
  const n = (value: number) => formatNumber(value, i18n.language);
  if (score.isPending || result.isPending) {
    return <Loading rows={6} />;
  }
  if (!score.data || !result.data) {
    return <Note tone="warn">{t('ux.result.unavailable')}</Note>;
  }
  const data: RunScore = score.data;
  const recorded = anatomy.data?.interpretation?.recorded ?? null;
  const deciding = data.verdicts.find((verdict) => verdict.score.stepNo === step) ?? data.verdicts[0];
  const action = deciding?.score.finalAction ?? recorded?.finalAction ?? null;
  const contexa = data.business.D;
  const requested = labCase?.requests[0]?.items ?? labCase?.steps ?? 0;
  const prediction = runs.prediction(caseKey);
  const verdict = verdictOf(action);
  const look = UX_VERDICTS[verdict];
  const existing = EXISTING.map((control) => data.business[control]?.result ?? null);
  const missedAll = existing.every((value) => value === 'MISSED');
  const passedAll = existing.every((value) => value === 'PASSED');
  const stopped = existing.filter((value) => value === 'STOPPED' || value === 'HALTED').length;
  const timings = anatomy.data?.interpretation?.timings ?? null;
  const applied = deciding?.score.applied ?? recorded?.applied ?? null;
  return (
    <>
      <section className={styles.verdict} aria-labelledby="result-title" data-tone={look.tone}>
        <span className={styles.verdictIcon} data-tone={look.tone}>
          <Icon name={look.icon} size="xxl" />
        </span>
        <div className={styles.verdictMain}>
          <h1 id="result-title" tabIndex={-1} className={styles.verdictTitle}>
            {t(conclusionKey(data), { n: n(requested), exposed: n(contexa?.exposedItems ?? 0) })}
          </h1>
          <p className={styles.verdictSub}>
            {missedAll
              ? t('ux.result.existing.allMissed')
              : passedAll
                ? t('ux.result.existing.allPassed')
                : t('ux.result.existing.mixed', { stopped, passed: 4 - stopped })}{' '}
            {action === 'CHALLENGE' ? t('ux.result.challengeMeans') : null}
          </p>
          <StoredCheckRecord check={anatomy.data?.recovery?.challenge} className={styles.checkRecord} />
        </div>
        <dl className={styles.verdictSide}>
          {steps > 1 ? (
            <>
              <dt>{t('ux.result.decidingStep')}</dt>
              <dd>{t('ux.result.decidingStepValue', { n: step, total: steps })}</dd>
            </>
          ) : null}
          <dt>{t('ux.result.decision')}</dt>
          <dd>
            <VerdictBadge verdict={verdict} />
          </dd>
          {prediction?.call.engine ? (
            <>
              <dt>{t('ux.review.predict.title')}</dt>
              <dd>
                {prediction.engineSameStop === true ? (
                  <EvalBadge result="correct" />
                ) : prediction.engineSameStop === false ? (
                  <Badge tone="none">{t('ux.result.predictionDiffers')}</Badge>
                ) : null}{' '}
                {t(`ux.review.predict.${prediction.call.engine === 'ALLOW' ? 'ALLOW' : 'BLOCK'}.title`)}
              </dd>
            </>
          ) : null}
          <dt>{t('ux.result.decisionTime')}</dt>
          <dd>
            {timings?.totalAnalysisMs != null
              ? t('ux.time.seconds', { value: formatDuration(timings.totalAnalysisMs, i18n.language) })
              : '—'}
            {applied
              ? ` · ${t(`ux.live.applied.${applied === 'NEXT_REQUEST' ? 'NEXT_REQUEST' : 'BEFORE_RESPONSE'}`)}`
              : ''}
          </dd>
          <dt>{t('ux.result.runId')}</dt>
          <dd>
            <CodeChip value={runId} copy />
          </dd>
        </dl>
      </section>

      <div className={styles.grid}>
        <div className={styles.column}>
          <Exports score={data} requested={requested} runId={runId} step={step} steps={steps} />
          <Latency
            result={result.data}
            totalAnalysisMs={timings?.totalAnalysisMs ?? null}
            applied={applied}
          />
        </div>
        <Evidence
          runId={runId}
          stepNo={step}
          risk={recorded?.riskScore ?? null}
          confidence={recorded?.confidence ?? null}
          reasoning={recorded?.reasoning ?? null}
          reasoningCode={recorded?.reasoningCode ?? null}
        />
      </div>

      <NextChecks scenario={scenario} runId={runId} />
    </>
  );
}

/** The items each control handed over across the run, against the request's size, with the server's grading. */
function Exports({
  score,
  requested,
  runId,
  step,
  steps,
}: {
  readonly score: RunScore;
  readonly requested: number;
  readonly runId: string;
  /** The request the result rests on; its stored responses fold under the bars. */
  readonly step: number;
  readonly steps: number;
}) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const most = Math.max(
    requested,
    ...CONTROL_ORDER.map((control) => score.business[control]?.exposedItems ?? 0),
    1,
  );
  return (
    <section className={styles.card} aria-labelledby="exports-title">
      <header className={styles.cardHead}>
        <h2 id="exports-title" className={styles.cardTitle}>
          {t('ux.result.exports.title')}
        </h2>
        <p className={styles.cardSub}>{t('ux.result.exports.sub')}</p>
      </header>
      <ul className={styles.exports}>
        {CONTROL_ORDER.map((control) => {
          const business = score.business[control];
          const graded = evalOf(business?.result);
          const items = business?.exposedItems ?? 0;
          return (
            <li key={control} className={styles.exportRow} data-contexa={control === 'D' || undefined}>
              <span className={styles.exportName}>{t(`ux.control.short.${control}`)}</span>
              <span className={styles.exportBar}>
                <Bar
                  label={t(`ux.control.short.${control}`)}
                  value={items / most}
                  tone={CONTROL_TONE[control]}
                  thick
                />
              </span>
              <span className={styles.exportValue}>{n(items)}</span>
              <span>{graded ? <EvalBadge result={graded} /> : null}</span>
            </li>
          );
        })}
        <li className={[styles.exportRow, styles.axis].join(' ')} aria-hidden="true">
          <span />
          <span className={styles.axisTrack}>
            <span>0</span>
            <span>{n(Math.round(most / 2))}</span>
            <span>{t('ux.facts.items', { count: most, n: n(most) })}</span>
          </span>
          <span />
          <span />
        </li>
      </ul>
      <Responses runId={runId} step={step} steps={steps} />
    </section>
  );
}

/**
 * What each control actually answered to the request, as the run stored it (P-8, the old 2-3 proof): the request line,
 * when it was sent (UTC), the HTTP status and the start of the body, folded under the bars.
 */
function Responses({
  runId,
  step,
  steps,
}: {
  readonly runId: string;
  readonly step: number;
  readonly steps: number;
}) {
  const { t } = useTranslation();
  const responses = useStepResponses(runId, step).data ?? [];
  if (responses.length === 0) {
    return null;
  }
  const zone = t('ux.time.zone');
  return (
    <details className={styles.responses}>
      <summary>
        {t('ux.result.responses.more')}
        {steps > 1 ? ` · ${t('ux.result.decidingStepValue', { n: step, total: steps })}` : null}
      </summary>
      <p className={styles.responsesNote}>{t('ux.result.responses.note')}</p>
      <ul className={styles.responseList}>
        {responses.map((response) => {
          const control = t(`ux.control.short.${response.control}`, { defaultValue: response.control });
          return (
            <li key={response.control} className={styles.response}>
              <p className={styles.responseHead}>
                <b>{control}</b>
                <code>
                  {response.method} {response.path}
                </code>
                <span>HTTP {response.httpStatus ?? '—'}</span>
                <span>
                  {response.sentAt
                    ? t('ux.result.responses.sent', { time: formatUtc(response.sentAt), zone })
                    : '—'}
                </span>
              </p>
              <pre
                className={styles.responseBody}
                tabIndex={0}
                aria-label={t('ux.result.responses.body', { control })}
              >
                {response.excerpt ?? '—'}
              </pre>
            </li>
          );
        })}
      </ul>
    </details>
  );
}

/** How long each side took and how Contexa's decision applied (DEC-18: response time against decision time). */
function Latency({
  result,
  totalAnalysisMs,
  applied,
}: {
  readonly result: {
    readonly layers: readonly {
      readonly control: string;
      readonly evidence: { readonly responseMs: number | null };
    }[];
  };
  readonly totalAnalysisMs: number | null;
  readonly applied: string | null;
}) {
  const { t, i18n } = useTranslation();
  const stats = useStats();
  const times = result.layers
    .filter((layer) => layer.control !== 'D')
    .map((layer) => layer.evidence.responseMs)
    .filter((value): value is number => value !== null);
  const contexa = result.layers.find((layer) => layer.control === 'D')?.evidence.responseMs ?? null;
  const p50 = stats.data?.decisionTime.p50Ms ?? null;
  const p95 = stats.data?.decisionTime.p95Ms ?? null;
  const s = (ms: number) => t('ux.time.seconds', { value: formatDuration(ms, i18n.language) });
  return (
    <section className={styles.card} aria-labelledby="latency-title">
      <header className={styles.cardHead}>
        <h2 id="latency-title" className={styles.cardTitle}>
          {t('ux.result.latency.title')}
        </h2>
        <p className={styles.cardSub}>
          {t(applied === 'NEXT_REQUEST' ? 'ux.result.latency.subNext' : 'ux.result.latency.subBefore')}
        </p>
      </header>
      <dl className={styles.latency}>
        <dt>{t('ux.control.existing')}</dt>
        <dd>
          {times.length > 0 ? `${s(Math.min(...times))} ~ ${s(Math.max(...times))}` : '—'}
          <span>{t('ux.result.latency.existing')}</span>
        </dd>
        <dt>Contexa</dt>
        <dd>
          {totalAnalysisMs !== null ? t('ux.result.latency.decision', { value: s(totalAnalysisMs) }) : '—'}
          {contexa !== null ? ' · ' : null}
          {contexa !== null ? t('ux.result.latency.response', { value: s(contexa) }) : null}
          {p50 !== null && p95 !== null ? (
            <span>{t('ux.result.latency.demo', { p50: s(p50), p95: s(p95) })}</span>
          ) : null}
        </dd>
      </dl>
      <Note>{t('ux.result.latency.async')}</Note>
    </section>
  );
}

/** The three next checks (F-6, F-7): the control run first, then the decision details and the standard benchmarks. */
function NextChecks({ scenario, runId }: { readonly scenario: PersonCase; readonly runId: string }) {
  const { t } = useTranslation();
  const runs = usePersonRuns();
  const pair = scenario.pair;
  const pairRun = pair ? runs.latest(pair) : null;
  const first =
    pair === null
      ? {
          title: t('ux.result.next.agent.title'),
          desc: t('ux.result.next.agent.desc'),
          to: '/simulate/agent',
          action: t('ux.result.next.agent.action'),
        }
      : pairRun
        ? {
            title: t('ux.result.next.compare.title'),
            desc: t('ux.result.next.compare.desc'),
            to: flowPath(scenario.key, 'result', '?tab=compare'),
            action: t('ux.compare.title'),
          }
        : {
            title: t(`ux.result.next.pair.${scenario.key}.title`),
            desc: t(`ux.result.next.pair.${scenario.key}.desc`),
            to: flowPath(pair, 'review'),
            action: t('ux.result.next.run', { key: pair }),
          };
  return (
    <section aria-labelledby="next-title" className={styles.next}>
      <div className={styles.nextHead}>
        <h2 id="next-title" className={styles.cardTitle}>
          {t('ux.result.next.title')}
        </h2>
        <p className={styles.cardSub}>{t('ux.result.next.sub')}</p>
      </div>
      <div className={styles.nextCards}>
        <article className={styles.nextCard} data-primary="true">
          <h3 className={styles.nextTitle}>{first.title}</h3>
          <p className={styles.nextDesc}>{first.desc}</p>
          <ButtonLink to={first.to} variant="primary" iconAfter="arrow-right">
            {first.action}
          </ButtonLink>
        </article>
        <article className={styles.nextCard}>
          <h3 className={styles.nextTitle}>{t('ux.result.next.detail.title')}</h3>
          <p className={styles.nextDesc}>{t('ux.result.next.detail.desc')}</p>
          <ButtonLink to={`/runs/${encodeURIComponent(runId)}`}>
            {t('ux.result.next.detail.action')}
          </ButtonLink>
        </article>
        <article className={styles.nextCard}>
          <h3 className={styles.nextTitle}>{t('ux.result.next.bench.title')}</h3>
          <p className={styles.nextDesc}>{t('ux.result.next.bench.desc')}</p>
          <ButtonLink to="/benchmarks">{t('ux.result.next.bench.action')}</ButtonLink>
        </article>
      </div>
    </section>
  );
}
