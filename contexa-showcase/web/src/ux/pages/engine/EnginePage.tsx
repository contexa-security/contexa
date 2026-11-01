import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { useAnatomy, useReceived, type DecisionAnatomyView } from '../../../api/anatomy';
import { useEngineActions } from '../../../api/engine';
import { useLatestRelease, type StoredRelease } from '../../../api/follow';
import { useHook } from '../../../api/hook';
import { useJourney } from '../../../api/journey';
import { useLabOptions } from '../../../api/lab';
import { useMeasuredCase, type MeasuredCase } from '../../../api/measured';
import { useRunQuality } from '../../../api/promptQuality';
import { useBaseline, useRunScore, useStats, useVisitor } from '../../../api/queries';
import type { CaseResult } from '../../../api/types';
import type { UxIconName } from '../../ui/Icon';
import { formatDuration, formatNumber, formatUtc } from '../../format';
import { useScenarioTitle } from '../../runs/runLog';
import { contextChips, evalOf, verdictOf } from '../../simulate/person';
import {
  Badge,
  Bar,
  ButtonLink,
  CodeChip,
  ErrorState,
  EvalBadge,
  Icon,
  Loading,
  Note,
  PageHead,
  TabPanel,
  Tabs,
  VerdictBadge,
} from '../../ui';
import { EvidenceTab, IntegrityTab, PromptTab } from '../runs/detailTabs';
import styles from './Engine.module.css';

const TABS = ['flow', 'baseline', 'facts', 'prompt', 'seal'] as const;
type TabId = (typeof TABS)[number];
/** The case the engine is shown on (the account takeover of the start of the demo) and the comparison of learning. */
const MAIN = 'S13';
const LEARNS = 'A6T';
const SYNC = 'A3';
const ASYNC = 'A3A';
/** The same person's normal work sent both ways (옛 M-timing의 정상 업무 줄). */
const NORMAL_SYNC = 'A3T';
const NORMAL_ASYNC = 'A3TA';
/** The stages of a release in order, each with the stored time it happened (옛 M-follow ReleaseRecord). */
const RELEASE_STAGES = [
  ['blocked', 'blocked_at'],
  ['code', 'code_requested_at'],
  ['verified', 'verified_at'],
  ['requested', 'requested_at'],
  ['approved', 'approved_at'],
  ['resent', 'reissue_sent_at'],
] as const;

/**
 * The AI decision engine (기획안 7.8, DEC-45): how one request is decided, stage by stage, with this run's own values,
 * then the baseline it learned from, the facts it cited, the prompt it was given and the seal of the decision. The run
 * is the visitor's latest account-takeover run, else the public recorded one; `?run=` names another.
 */
export default function EnginePage() {
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const hook = useHook();
  const own =
    [...(journey.data?.runs ?? [])]
      .reverse()
      .find((run) => run.scenarioKey === MAIN && !run.lab && run.status === 'COMPLETED')?.runId ?? null;
  const published = hook.data?.attacker.runId ?? null;
  const asked = params.get('run');
  // DEC-45: the visitor's own latest account-takeover run first, else the public recorded one.
  const runId = asked ?? (journey.isPending && visitor.isSuccess ? null : (own ?? published));
  const anatomy = useAnatomy(runId, 1);
  const score = useRunScore(runId, 'engine', 1);
  const tab: TabId = TABS.includes(params.get('tab') as TabId) ? (params.get('tab') as TabId) : 'flow';
  const titleOf = useScenarioTitle();
  const set = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value === null) {
      next.delete(key);
    } else {
      next.set(key, value);
    }
    setParams(next, { replace: true });
  };
  const whose = runId === own ? 'own' : runId === published ? 'public' : 'other';
  const switcher =
    own && runId !== own ? (
      <ButtonLink to={`?${new URLSearchParams({ tab, run: own }).toString()}`} variant="secondary" icon="refresh-cw">
        {t('ux.engine.toOwn')}
      </ButtonLink>
    ) : published && runId !== published ? (
      <ButtonLink to={`?${new URLSearchParams({ tab }).toString()}`} variant="secondary" icon="refresh-cw">
        {t('ux.engine.toPublic')}
      </ButtonLink>
    ) : null;
  return (
    <>
      <PageHead
        title={t('ux.engine.title')}
        desc={t('ux.engine.desc')}
        actions={
          <span className={styles.base}>
            <span className={styles.baseLabel}>{t(`ux.engine.base.${whose}`)}</span>
            {runId ? <CodeChip value={runId} /> : null}
            {switcher}
          </span>
        }
      />
      <Tabs
        idBase="engine"
        label={t('ux.engine.tabs')}
        value={tab}
        onChange={(id) => set('tab', id)}
        items={TABS.map((id) => ({ id, label: t(`ux.engine.tab.${id}`) }))}
      />
      <TabPanel idBase="engine" id={tab}>
        {!runId || anatomy.isPending ? (
          hook.isError && !asked ? (
            <ErrorState>{t('ux.engine.noRun')}</ErrorState>
          ) : (
            <Loading rows={6} />
          )
        ) : !anatomy.data ? (
          // ST-50: the run's record could not be read.
          <ErrorState onRetry={() => void anatomy.refetch()}>{t('ux.detail.failed')}</ErrorState>
        ) : tab === 'flow' ? (
          <FlowTab
            runId={runId}
            anatomy={anatomy.data}
            title={titleOf(MAIN, score.data?.title, i18n.language)}
            decidedAt={score.data?.verdicts[0]?.decidedAt ?? null}
          />
        ) : tab === 'baseline' ? (
          <BaselineTab caseKey={score.data?.scenarioKey ?? MAIN} anatomy={anatomy.data} />
        ) : tab === 'facts' ? (
          <EvidenceTab runId={runId} step={1} anatomy={anatomy.data} score={score.data ?? null} />
        ) : tab === 'prompt' ? (
          <PromptTab runId={runId} step={1} anatomy={anatomy.data} score={score.data ?? null} />
        ) : (
          <IntegrityTab runId={runId} step={1} anatomy={anatomy.data} score={score.data ?? null} />
        )}
      </TabPanel>
    </>
  );
}

/** A window as the record writes it ("7d", "24h") in the visitor's words. */
function windowWords(t: ReturnType<typeof useTranslation>['t'], window: string | null): string {
  const match = window ? /^(\d+)([dh])$/.exec(window) : null;
  if (!match) {
    return window ?? '—';
  }
  return t(match[2] === 'd' ? 'ux.engine.window.days' : 'ux.engine.window.hours', { n: Number(match[1]) });
}

/** A held decision's time in the largest whole unit (15 s, 30 min, 1 h). */
function heldWords(t: ReturnType<typeof useTranslation>['t'], seconds: number): string {
  if (seconds >= 3600 && seconds % 3600 === 0) {
    return t('ux.engine.held.hours', { n: seconds / 3600 });
  }
  if (seconds >= 60 && seconds % 60 === 0) {
    return t('ux.engine.held.minutes', { n: seconds / 60 });
  }
  return t('ux.engine.held.seconds', { n: seconds });
}

interface Stage {
  readonly id: string;
  readonly icon: UxIconName;
  readonly value: ReactNode;
  readonly raw: string;
}

/** 판정 흐름: the seven stages with this run's values, then the learning, the seal, when it applied and what follows. */
function FlowTab({
  runId,
  anatomy,
  title,
  decidedAt,
}: {
  readonly runId: string;
  readonly anatomy: DecisionAnatomyView;
  readonly title: string;
  readonly decidedAt: string | null;
}) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const received = useReceived(runId, 1);
  const quality = useRunQuality(runId, 1);
  const recorded = anatomy.interpretation.recorded;
  const timings = anatomy.interpretation.timings;
  const calls = anatomy.interpretation.calls;
  const figures = anatomy.figures;
  const lines = anatomy.promptLines;
  const seal = quality.data?.seal ?? null;
  const chips = received.data ? contextChips(t, received.data.businessFacts) : [];
  const promptTokens = calls.reduce((sum, call) => sum + (call.promptTokens ?? 0), 0);
  const stages: readonly Stage[] = [
    {
      id: 'learn',
      icon: 'graduation-cap',
      value:
        figures.baselineBefore !== null
          ? t('ux.engine.stage.learn.value', {
              n: n(figures.baselineBefore),
              window: windowWords(t, figures.workProfileWindow),
              observed: n(figures.workProfileObservations ?? 0),
            })
          : '—',
      raw: 'BaselineStatus',
    },
    {
      id: 'context',
      icon: 'briefcase',
      value: chips.length > 0 ? chips.slice(0, 3).join(' · ') : '…',
      raw: 'Policy',
    },
    {
      id: 'compare',
      icon: 'git-compare-arrows',
      value:
        figures.departureCount !== null
          ? t('ux.engine.stage.compare.value', {
              out: n(figures.departureCount),
              of: n(received.data?.comparedCount ?? 0),
              sensitivity: anatomy.context.resource?.sensitivity ?? '—',
            })
          : '—',
      raw: 'Deviations',
    },
    {
      id: 'prompt',
      icon: 'file-text',
      value: lines
        ? t('ux.engine.stage.prompt.value', { system: n(lines.system), user: n(lines.user), total: n(lines.total) })
        : '—',
      raw: quality.data?.bundle?.version ? `bundle ${quality.data.bundle.version}` : 'bundle',
    },
    {
      id: 'model',
      icon: 'sparkles',
      value: t('ux.engine.stage.model.value', {
        model: calls[0]?.model ?? '—',
        calls: n(calls.length),
        tokens: n(promptTokens),
        seconds: timings?.llmLatencyMs != null ? formatDuration(timings.llmLatencyMs, i18n.language) : '—',
      }),
      raw: `proposedAction ${recorded.proposedAction ?? '—'}`,
    },
    {
      id: 'apply',
      icon: 'shield-check',
      value: t('ux.engine.stage.apply.value', {
        codes: n(quality.data?.reasonCodes.length ?? 0),
        applied: recorded.applied
          ? t(`ux.live.applied.${recorded.applied === 'NEXT_REQUEST' ? 'NEXT_REQUEST' : 'BEFORE_RESPONSE'}`)
          : '—',
      }),
      raw: `finalAction ${recorded.finalAction ?? '—'}`,
    },
    {
      id: 'seal',
      icon: 'lock',
      value:
        figures.baselineBefore !== null && figures.baselineAfter !== null
          ? t(figures.baselineAfter > figures.baselineBefore ? 'ux.engine.stage.seal.learned' : 'ux.engine.stage.seal.kept', {
              n: n(figures.baselineAfter - figures.baselineBefore),
            })
          : '—',
      raw: seal?.packageHash ? `sha256 ${seal.packageHash.slice(0, 6)}…${seal.packageHash.slice(-4)}` : 'sha256 …',
    },
  ];
  return (
    <div className={styles.stack}>
      <section className={styles.flow} aria-labelledby="engine-flow">
        <header className={styles.flowHead}>
          <h2 id="engine-flow" className="ux-sr-only">
            {t('ux.engine.flow.title')}
          </h2>
          <Icon name="workflow" size="sm" />
          <span>
            {title} · {decidedAt ? `${formatUtc(decidedAt)} ${t('ux.runs.utc')}` : ''} ·{' '}
          </span>
          <VerdictBadge verdict={verdictOf(recorded.finalAction)} />
          <span>
            {timings?.totalAnalysisMs != null
              ? t('ux.engine.total', { seconds: formatDuration(timings.totalAnalysisMs, i18n.language) })
              : ''}
          </span>
        </header>
        <ol className={styles.stages}>
          {stages.map((stage, index) => (
            <li key={stage.id} className={styles.stage}>
              <span className={styles.stageTop}>
                <span className={styles.stageNo}>{index + 1}</span>
                <Icon name={stage.icon} size="sm" />
              </span>
              <b className={styles.stageName}>{t(`ux.engine.stage.${stage.id}.name`)}</b>
              <span className={styles.stageValue}>{stage.value}</span>
              <code className={styles.stageRaw}>{stage.raw}</code>
            </li>
          ))}
        </ol>
      </section>
      <div className={styles.cards}>
        <LearningCard runId={runId} figures={figures} />
        <SealCard runId={runId} />
      </div>
      <div className={styles.cards}>
        <TimingCard />
        <FollowCard />
      </div>
    </div>
  );
}

/** 기준선 학습 반영: this run against a measured run of normal work that was learned (DEC-45). */
function LearningCard({ runId, figures }: { readonly runId: string; readonly figures: DecisionAnatomyView['figures'] }) {
  const { t, i18n } = useTranslation();
  const measured = useMeasuredCase(LEARNS);
  const other = measured.data?.middleRun ?? null;
  const otherAnatomy = useAnatomy(other, 1);
  const options = useLabOptions();
  // 옛 3-1: the measured run is another case's, so its row names the employee the case sends as (the case list).
  const learnsAs = options.data?.cases.find((candidate) => candidate.key === LEARNS)?.conditions.employee ?? null;
  const person = options.data?.employees.find((candidate) => candidate.key === learnsAs) ?? null;
  const n = (value: number) => formatNumber(value, i18n.language);
  const row = (label: string, id: string | null, before: number | null, after: number | null) => (
    <li className={styles.learnRow}>
      <span>
        <b>{label}</b>
        {id ? <code className={styles.raw}>{id}</code> : null}
      </span>
      <span className={styles.learnNumbers}>
        {before !== null && after !== null ? (
          <>
            {n(before)} → {n(after)}{' '}
            <Badge tone={after > before ? 'allow' : 'none'}>
              {after > before ? t('ux.detail.learning.added', { n: n(after - before) }) : t('ux.detail.learning.none')}
            </Badge>
          </>
        ) : (
          '…'
        )}
      </span>
    </li>
  );
  return (
    <section className={styles.card} aria-labelledby="engine-learning">
      <h2 id="engine-learning" className={styles.cardTitle}>
        {t('ux.engine.learning.title')}
      </h2>
      <p className={styles.cardSub}>{t('ux.engine.learning.sub')}</p>
      <ul className={styles.learn}>
        {row(t('ux.engine.learning.this'), runId, figures.baselineBefore, figures.baselineAfter)}
        {row(
          person
            ? t('ux.engine.learning.otherOf', {
                name: t(`ux.person.${person.key}`, { defaultValue: person.displayName }),
              })
            : t('ux.engine.learning.other'),
          other,
          otherAnatomy.data?.figures.baselineBefore ?? null,
          otherAnatomy.data?.figures.baselineAfter ?? null,
        )}
      </ul>
    </section>
  );
}

/** 무결성 봉인: the seal of this decision and the inspection's verdict, with the demo's own retention. */
function SealCard({ runId }: { readonly runId: string }) {
  const { t } = useTranslation();
  const quality = useRunQuality(runId, 1);
  const seal = quality.data?.seal ?? null;
  const inspection = quality.data?.inspection ?? null;
  const counts = (inspection?.checks ?? []).reduce(
    (sum, check) => ({
      matched: sum.matched + check.matched,
      mismatched: sum.mismatched + check.mismatched,
      unverifiable: sum.unverifiable + check.unverifiable,
    }),
    { matched: 0, mismatched: 0, unverifiable: 0 },
  );
  return (
    <section className={styles.card} aria-labelledby="engine-seal">
      <h2 id="engine-seal" className={styles.cardTitle}>
        {t('ux.detail.integrity.seal')}
      </h2>
      <p className={styles.cardSub}>{t('ux.engine.seal.sub')}</p>
      {quality.isPending ? (
        <Loading rows={3} />
      ) : (
        <dl className={styles.kv}>
          <dt>{t('ux.detail.integrity.hash')}</dt>
          <dd>
            <code className={styles.raw}>
              {seal?.packageHash ? `sha256 ${seal.packageHash.slice(0, 6)}…${seal.packageHash.slice(-4)}` : '—'}
            </code>
          </dd>
          <dt>{t('ux.detail.integrity.at')}</dt>
          <dd>{seal?.capturedAt ? `${formatUtc(seal.capturedAt)} ${t('ux.runs.utc')}` : '—'}</dd>
          <dt>{t('ux.engine.seal.result')}</dt>
          <dd>
            {inspection
              ? t('ux.engine.seal.counts', {
                  verdict: t(`ux.detail.integrity.verdict.${inspection.verdict}`, { defaultValue: inspection.verdict }),
                  matched: counts.matched,
                  mismatched: counts.mismatched,
                  unverifiable: counts.unverifiable,
                })
              : t('ux.detail.integrity.noInspection')}
          </dd>
          <dt>{t('ux.engine.seal.scope')}</dt>
          <dd>{t('ux.engine.seal.scopeValue')}</dd>
        </dl>
      )}
      <ButtonLink to={`/runs/${encodeURIComponent(runId)}?tab=integrity`} size="sm">
        {t('ux.engine.seal.detail')}
      </ButtonLink>
    </section>
  );
}

/**
 * 판정 적용 시점 (옛 M-timing): the same export decided before the response and from the next request, as measured,
 * then the same person's normal work sent both ways; each line ends with the results the server counted over its runs.
 */
function TimingCard() {
  const { t, i18n } = useTranslation();
  const sync = useMeasuredCase(SYNC);
  const async = useMeasuredCase(ASYNC);
  const normalSync = useMeasuredCase(NORMAL_SYNC);
  const normalAsync = useMeasuredCase(NORMAL_ASYNC);
  const s = (ms: number) => formatDuration(ms, i18n.language);
  const n = (value: number) => formatNumber(value, i18n.language);
  // A range whose two ends are the same is one value.
  const range = (value: { readonly min: number; readonly max: number } | null, write: (x: number) => string) =>
    value ? (value.min === value.max ? write(value.min) : `${write(value.min)}~${write(value.max)}`) : '—';
  const line = (kind: 'sync' | 'async', data: MeasuredCase | undefined) =>
    data ? (
      <li className={styles.timingRow}>
        <b>{t(`ux.engine.timing.${kind}`)}</b>
        <span>
          {t('ux.engine.timing.value', {
            response: range(data.responseMs, s),
            analysis: range(data.analysisMs, s),
            exposed: range(data.exposedItems, n),
            runs: n(data.runs),
          })}
        </span>
        <span className={styles.results}>
          {Object.entries(data.results).map(([result, count]) => {
            const graded = evalOf(result as CaseResult);
            return (
              <span key={result} className={styles.result}>
                {graded ? <EvalBadge result={graded} /> : <code className={styles.raw}>{result}</code>}
                {t('ux.engine.timing.resultCount', { n: n(count) })}
              </span>
            );
          })}
        </span>
      </li>
    ) : null;
  return (
    <section className={styles.card} aria-labelledby="engine-timing">
      <h2 id="engine-timing" className={styles.cardTitle}>
        {t('ux.engine.timing.title')}
      </h2>
      <p className={styles.cardSub}>{t('ux.engine.timing.sub')}</p>
      {sync.isPending || async.isPending ? <Loading rows={2} /> : null}
      {!sync.data && !async.data && !sync.isPending && !async.isPending ? <Note>{t('ux.engine.timing.none')}</Note> : null}
      {sync.data || async.data ? (
        <>
          <h3 className={styles.subTitle}>{t('ux.engine.timing.attack')}</h3>
          <ul className={styles.timing} aria-label={t('ux.engine.timing.attack')}>
            {line('sync', sync.data)}
            {line('async', async.data)}
          </ul>
        </>
      ) : null}
      {normalSync.data || normalAsync.data ? (
        <>
          <h3 className={styles.subTitle}>{t('ux.engine.timing.normal')}</h3>
          <ul className={styles.timing} aria-label={t('ux.engine.timing.normal')}>
            {line('sync', normalSync.data)}
            {line('async', normalAsync.data)}
          </ul>
        </>
      ) : null}
    </section>
  );
}

/** 후속 조치 (옛 M-follow): how long each decision stays in force, and how many of each the demo has made. */
function FollowCard() {
  const { t, i18n } = useTranslation();
  const actions = useEngineActions();
  const stats = useStats();
  const n = (value: number) => formatNumber(value, i18n.language);
  const total = Object.values(stats.data?.engineActions ?? {}).reduce((sum, value) => sum + value, 0);
  return (
    <section className={styles.card} aria-labelledby="engine-follow">
      <h2 id="engine-follow" className={styles.cardTitle}>
        {t('ux.engine.follow.title')}
      </h2>
      <p className={styles.cardSub}>{t('ux.engine.follow.sub')}</p>
      {actions.isPending ? <Loading rows={4} /> : null}
      {actions.data ? (
        <ul className={styles.follow}>
          {(['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'] as const).map((action) => {
            const rule = actions.data[action];
            const count = stats.data?.engineActions?.[action] ?? null;
            return (
              <li key={action}>
                <VerdictBadge verdict={action} />
                <span>
                  {rule
                    ? t(rule.ttlSeconds === null ? 'ux.engine.follow.until' : 'ux.engine.follow.ttl', {
                        status: rule.httpStatus,
                        held: rule.ttlSeconds === null ? '' : heldWords(t, rule.ttlSeconds),
                      })
                    : '—'}
                </span>
                {count !== null && total > 0 ? (
                  <span className={styles.followCount}>
                    <Bar label={t(`ux.runs.verdict.${action}`)} value={count / total} tone="link" />
                    {n(count)}
                  </span>
                ) : null}
              </li>
            );
          })}
        </ul>
      ) : actions.isError ? (
        <Note>{t('ux.engine.follow.none')}</Note>
      ) : null}
      <ReleaseDetails />
    </section>
  );
}

/** The latest block of the demo that was actually released (옛 M-follow ReleaseRecord), read once it is opened. */
function ReleaseDetails() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <details className={styles.more} onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary>{t('ux.engine.follow.release.title')}</summary>
      {open ? <ReleaseRecord /> : null}
    </details>
  );
}

function ReleaseRecord() {
  const { t } = useTranslation();
  const latest = useLatestRelease();
  const record = latest.data ?? null;
  const anatomy = useAnatomy(record?.runId ?? null, record?.stepNo ?? 1);
  // The stored release (run_release) as the run's anatomy carries it.
  const release = (anatomy.data?.recovery?.release ?? null) as StoredRelease | null;
  if (latest.isPending || (record !== null && anatomy.isPending)) {
    return <Loading rows={3} />;
  }
  if (record === null || release === null) {
    return <Note>{t('ux.engine.follow.release.none')}</Note>;
  }
  const address = `/runs/${encodeURIComponent(record.runId)}${record.stepNo > 1 ? `?step=${record.stepNo}` : ''}`;
  return (
    <div className={styles.moreBody}>
      {record.forcedAction ? (
        <p className={styles.forced}>
          <Badge tone="line">{t('ux.engine.follow.release.forced', { action: record.forcedAction })}</Badge>
          <span>{t('ux.engine.follow.release.forcedNote')}</span>
        </p>
      ) : null}
      <ol className={styles.release} aria-label={t('ux.engine.follow.release.stages')}>
        {RELEASE_STAGES.map(([id, field]) => {
          const at = release[field];
          return (
            <li key={id} className={styles.releaseStage}>
              <span>{t(`ux.engine.follow.release.stage.${id}`)}</span>
              {at ? (
                <time dateTime={at} title={at}>
                  {formatUtc(at)} {t('ux.runs.utc')}
                </time>
              ) : (
                <span>—</span>
              )}
            </li>
          );
        })}
      </ol>
      <p className={styles.cardSub}>
        {t('ux.engine.follow.release.run')} · <Link to={address}>{record.runId}</Link>
      </p>
    </div>
  );
}

/** 행위 기준선: what the engine learned of the person whose account sends the request (옛 M-learn · M-learned). */
function BaselineTab({ caseKey, anatomy }: { readonly caseKey: string; readonly anatomy: DecisionAnatomyView }) {
  const { t, i18n } = useTranslation();
  const options = useLabOptions();
  const employee = options.data?.cases.find((candidate) => candidate.key === caseKey)?.conditions.employee ?? null;
  const person = options.data?.employees.find((candidate) => candidate.key === employee) ?? null;
  const baseline = useBaseline(employee);
  const n = (value: number) => formatNumber(value, i18n.language);
  const hourList = (hours: readonly number[]) =>
    hours.length > 0 ? hours.map((hour) => t('ux.engine.baseline.hour', { h: hour })).join(', ') : '—';
  if (options.isPending || baseline.isPending) {
    return <Loading rows={6} />;
  }
  if (!baseline.data) {
    return <Note tone="warn">{t('ux.engine.baseline.none')}</Note>;
  }
  const data = baseline.data;
  const peakHour = Math.max(1, ...data.learned.hours);
  const peakDay = Math.max(1, ...data.learned.weekdays);
  return (
    <div className={styles.stack}>
      <section className={styles.card} aria-labelledby="engine-baseline">
        <h2 id="engine-baseline" className={styles.cardTitle}>
          {t('ux.engine.baseline.title', { name: t(`ux.person.${data.employeeKey}`, { defaultValue: data.displayName }) })}
        </h2>
        <p className={styles.cardSub}>
          {t('ux.engine.baseline.sub', {
            n: n(data.learned.requests),
            sent: n(data.sent),
            from: data.taught.from ? formatUtc(data.taught.from).slice(0, 10) : '—',
            to: data.taught.to ? formatUtc(data.taught.to).slice(0, 10) : '—',
          })}
        </p>
        <div className={styles.baselineGrid}>
          <figure className={styles.histogram}>
            <figcaption>{t('ux.engine.baseline.hours')}</figcaption>
            <ol aria-label={t('ux.engine.baseline.hours')}>
              {data.learned.hours.map((count, hour) => (
                <li key={hour} className={styles.hbar} title={`${hour}:00 · ${count}`}>
                  <i style={{ blockSize: `${(count / peakHour) * 100}%` }} aria-hidden="true" />
                  <span className="ux-sr-only">
                    {hour}:00 {count}
                  </span>
                </li>
              ))}
            </ol>
            <span className={styles.axis} aria-hidden="true">
              <span>0</span>
              <span>12</span>
              <span>23</span>
            </span>
          </figure>
          <figure className={styles.histogram} data-days="true">
            <figcaption>{t('ux.engine.baseline.days')}</figcaption>
            <ol aria-label={t('ux.engine.baseline.days')}>
              {data.learned.weekdays.map((count, day) => (
                <li key={day} className={styles.hbar} title={`${t(`ux.engine.day.${day}`)} · ${count}`}>
                  <i style={{ blockSize: `${(count / peakDay) * 100}%` }} aria-hidden="true" />
                  <span className={styles.dayName}>{t(`ux.engine.day.${day}`)}</span>
                </li>
              ))}
            </ol>
          </figure>
          <dl className={styles.kv}>
            <dt>{t('ux.engine.baseline.networks')}</dt>
            <dd>{data.learned.networks.join(', ') || '—'}</dd>
            <dt>{t('ux.engine.baseline.office')}</dt>
            <dd>{person?.officeNetwork ?? '—'}</dd>
            <dt>{t('ux.engine.baseline.devices')}</dt>
            <dd>{data.learned.devices.join(', ') || '—'}</dd>
            <dt>{t('ux.engine.baseline.taught')}</dt>
            <dd>
              {t('ux.engine.baseline.taughtValue', {
                reads: n(data.taught.reads),
                downloads: n(data.taught.downloads),
                exports: n(data.taught.exports),
              })}
            </dd>
            <dt>{t('ux.engine.baseline.projects')}</dt>
            <dd>
              {Object.entries(data.taught.projects)
                .map(([project, count]) => t('ux.engine.baseline.projectValue', { project, n: n(count) }))
                .join(', ') || '—'}
            </dd>
            <dt>{t('ux.engine.baseline.size')}</dt>
            <dd>
              {data.taught.exportItemsMin !== null && data.taught.exportItemsMax !== null
                ? t('ux.engine.baseline.sizeValue', { min: n(data.taught.exportItemsMin), max: n(data.taught.exportItemsMax) })
                : '—'}
            </dd>
          </dl>
        </div>
        <details className={styles.more}>
          <summary>{t('ux.engine.baseline.requests', { n: n(data.requests.length) })}</summary>
          <div className={styles.moreBody}>
            <p className={styles.cardSub}>
              {t('ux.engine.baseline.counts', {
                sent: n(data.sent),
                allowed: n(data.allowed),
                learned: n(data.learned.requests),
              })}
            </p>
            <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
              <table className={styles.table}>
                <caption className="ux-sr-only">{t('ux.engine.baseline.table')}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t('ux.engine.baseline.col.no')}</th>
                    <th scope="col">{t('ux.engine.baseline.col.time')}</th>
                    <th scope="col">{t('ux.engine.baseline.col.request')}</th>
                    <th scope="col">{t('ux.engine.baseline.col.items')}</th>
                    <th scope="col">{t('ux.engine.baseline.col.verdict')}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.requests.map((request) => (
                    <tr key={request.no}>
                      <td>{request.no}</td>
                      <td>{formatUtc(request.companyTime)}</td>
                      <td>
                        <code className={styles.raw}>{request.path}</code>
                      </td>
                      <td>{request.items === null ? '—' : n(request.items)}</td>
                      <td>
                        {request.finalAction ? <VerdictBadge verdict={verdictOf(request.finalAction)} /> : '—'}
                        {request.identityCheckPassed ? ` · ${t('ux.engine.baseline.checked')}` : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </details>
        <details className={styles.more}>
          <summary>{t('ux.engine.baseline.states')}</summary>
          {data.hours ? (
            <div className={styles.moreBody}>
              <p className={styles.cardSub}>{t('ux.engine.baseline.statesSub')}</p>
              <dl className={styles.kv}>
                <dt>{t('ux.engine.baseline.state.personal')}</dt>
                <dd>{data.hours.personalBaselineStatus ? <code className={styles.raw}>{data.hours.personalBaselineStatus}</code> : '—'}</dd>
                <dt>{t('ux.engine.baseline.state.scope')}</dt>
                <dd>
                  {data.hours.roleScopeState ? <code className={styles.raw}>{data.hours.roleScopeState}</code> : '—'}
                  {data.hours.roleScopeState === 'PROVISIONAL' ? (
                    <span className={styles.why}>{t('ux.engine.baseline.state.scopeNote')}</span>
                  ) : null}
                </dd>
                <dt>{t('ux.engine.baseline.state.normalHours')}</dt>
                <dd>{hourList(data.hours.normalAccessHours)}</dd>
                <dt>{t('ux.engine.baseline.state.observedHours')}</dt>
                <dd>{hourList(data.hours.observedHours)}</dd>
                <dt>{t('ux.engine.baseline.state.run')}</dt>
                <dd>
                  <Link
                    to={`/runs/${encodeURIComponent(data.hours.runId)}${data.hours.stepNo > 1 ? `?step=${data.hours.stepNo}` : ''}`}
                  >
                    {data.hours.runId}
                  </Link>
                </dd>
              </dl>
            </div>
          ) : (
            <Note>{t('ux.engine.baseline.stateNone')}</Note>
          )}
        </details>
      </section>
      <section className={styles.card} aria-labelledby="engine-baseline-run">
        <h2 id="engine-baseline-run" className={styles.cardTitle}>
          {t('ux.engine.baseline.thisRun')}
        </h2>
        <p className={styles.cardSub}>{t('ux.detail.learning.sub')}</p>
        <p className={styles.bigNumbers}>
          {anatomy.figures.baselineBefore !== null && anatomy.figures.baselineAfter !== null
            ? t('ux.detail.learning.value', {
                from: n(anatomy.figures.baselineBefore),
                to: n(anatomy.figures.baselineAfter),
              })
            : t('ux.detail.learning.unknown')}
        </p>
      </section>
    </div>
  );
}
