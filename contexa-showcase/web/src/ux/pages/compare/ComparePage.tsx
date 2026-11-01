import { useState, type CSSProperties } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { useReceived } from '../../../api/anatomy';
import { useBenchmark } from '../../../api/benchmark';
import { useHook } from '../../../api/hook';
import { useJourney } from '../../../api/journey';
import { useLabOptions, useRecentLabRuns } from '../../../api/lab';
import { useLabDelta } from '../../../api/promptQuality';
import { useRunScore, useVisitor } from '../../../api/queries';
import { usePublicSettings } from '../../../api/settings';
import type { CaseResult } from '../../../api/types';
import { formatNumber, formatUtc } from '../../format';
import { decisionOf } from '../../runs/runLog';
import { deviceWords, evalOf, verdictOf } from '../../simulate/person';
import { EVAL_TONES } from '../../verdict';
import {
  Badge,
  ButtonLink,
  CodeChip,
  ErrorState,
  EvalBadge,
  Icon,
  Loading,
  Note,
  PageHead,
  Switch,
  TabPanel,
  Tabs,
  VerdictBadge,
} from '../../ui';
import styles from './Compare.module.css';

const TABS = ['rule', 'change', 'runs'] as const;
type TabId = (typeof TABS)[number];
const ATTACK = 'S13';
const STOPPING: ReadonlySet<string> = new Set(['STOPPED', 'PARTLY_STOPPED', 'HALTED']);
const NORMAL = 'S13T';

/**
 * Detection compared (기획안 7.9, DEC-46): the rule control and Contexa on the same request — the threshold rule on two
 * runs of the shared request, the visitor's composed runs with one condition changed, and the measured runs of every
 * scenario as dots per control. A new run with one change is the policy simulator's composition (DEC-33).
 */
export default function ComparePage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const tab: TabId = TABS.includes(params.get('tab') as TabId) ? (params.get('tab') as TabId) : 'rule';
  return (
    <>
      <PageHead title={t('ux.compareMenu.title')} desc={t('ux.compareMenu.desc')} />
      <Tabs
        idBase="compare"
        label={t('ux.compareMenu.tabs')}
        value={tab}
        onChange={(id) => setParams(new URLSearchParams({ tab: id }), { replace: true })}
        items={TABS.map((id) => ({ id, label: t(`ux.compareMenu.tab.${id}`) }))}
      />
      <TabPanel idBase="compare" id={tab}>
        {tab === 'rule' ? <RuleTab /> : tab === 'change' ? <ChangeTab /> : <RunsTab />}
      </TabPanel>
    </>
  );
}

/** The run of the shared request a side shows: the visitor's latest (ST-51), else the public recorded one. */
function useSides() {
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const hook = useHook();
  const latest = (key: string) =>
    [...(journey.data?.runs ?? [])].reverse().find((run) => run.scenarioKey === key && !run.lab && run.status === 'COMPLETED')
      ?.runId ?? null;
  const side = (key: string, published: string | null) => {
    const own = latest(key);
    return { key, runId: own ?? published, own: own !== null };
  };
  return {
    pending: hook.isPending,
    attack: side(ATTACK, hook.data?.attacker.runId ?? null),
    normal: side(NORMAL, hook.data?.owner.runId ?? null),
  };
}

function RuleTab() {
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const settings = usePublicSettings();
  const sides = useSides();
  const on = params.get('rule') !== 'off';
  const threshold = settings.data?.threshold ?? null;
  const n = (value: number) => formatNumber(value, i18n.language);
  const attack = useSide(sides.attack.runId);
  const normal = useSide(sides.normal.runId);
  const control = on ? 'C1' : 'B';
  // What the rule did (stopped or let through), not its grade: a missed attack and passed normal work were both let
  // through, so the rule could not tell them apart.
  const stoppedBy = (side: ReturnType<typeof useSide>) => {
    const result = side.score?.business[control]?.result ?? null;
    return result === null ? null : STOPPING.has(result);
  };
  const same = stoppedBy(attack) !== null && stoppedBy(attack) === stoppedBy(normal);
  const options = useLabOptions();
  const labCase = options.data?.cases.find((candidate) => candidate.key === ATTACK) ?? null;
  const smallest = options.data ? Math.min(...options.data.items) : null;
  const presets: readonly (readonly [string, string, string, string])[] = labCase
    ? [
        ['timeSlot', labCase.conditions.timeSlot === 'DAWN' ? 'AFTERNOON' : 'DAWN', 'ux.compareMenu.preset.time', ''],
        ...(smallest !== null ? [['items', String(smallest), 'ux.compareMenu.preset.items', n(smallest)] as const] : []),
        ['device', labCase.conditions.device === 'NEW' ? 'USUAL' : 'NEW', 'ux.compareMenu.preset.device', ''],
      ]
    : [];
  if (sides.pending || settings.isPending) {
    return <Loading rows={6} />;
  }
  return (
    <div className={styles.split}>
      <section className={styles.card} aria-labelledby="compare-rule">
        <div className={styles.ruleHead}>
          <Switch
            label={t(on ? 'ux.compareMenu.rule.on' : 'ux.compareMenu.rule.off')}
            checked={on}
            onChange={(value) => {
              const next = new URLSearchParams(params);
              if (value) {
                next.delete('rule');
              } else {
                next.set('rule', 'off');
              }
              setParams(next, { replace: true });
            }}
          />
          <div>
            <h2 id="compare-rule" className={styles.cardTitle}>
              {t('ux.compareMenu.rule.title')}
            </h2>
            <p className={styles.cardSub}>
              {threshold && threshold.nightStart && threshold.nightEnd && threshold.volumeLimit !== null
                ? t('ux.compareMenu.rule.line', {
                    start: threshold.nightStart,
                    end: threshold.nightEnd,
                    limit: n(threshold.volumeLimit),
                    days: threshold.dormantWindowDays ?? '—',
                  })
                : t('ux.compareMenu.rule.plain')}
            </p>
          </div>
        </div>
        <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
          <table className={styles.table}>
            <caption className="ux-sr-only">{t('ux.compareMenu.rule.title')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.compareMenu.col.run')}</th>
                <th scope="col">{t('ux.compareMenu.col.request')}</th>
                <th scope="col">{t(on ? 'ux.compareMenu.col.rule' : 'ux.compareMenu.col.signIn')}</th>
                <th scope="col">Contexa</th>
              </tr>
            </thead>
            <tbody>
              <SideRow name={t('ux.compareMenu.attack')} own={sides.attack.own} runId={sides.attack.runId} side={attack} control={control} />
              <SideRow name={t('ux.compareMenu.normal')} own={sides.normal.own} runId={sides.normal.runId} side={normal} control={control} />
            </tbody>
          </table>
        </div>
        {attack.score && normal.score ? (
          <div className={styles.insight}>
            <Icon name="lightbulb" />
            <div>
              <p className={styles.insightTitle}>
                {t(same ? 'ux.compareMenu.insight.same' : 'ux.compareMenu.insight.differs')}
              </p>
              <p className={styles.insightText}>{t(on ? 'ux.compareMenu.insight.textRule' : 'ux.compareMenu.insight.textSignIn')}</p>
            </div>
          </div>
        ) : null}
      </section>
      <section className={styles.card} aria-labelledby="compare-change">
        <h2 id="compare-change" className={styles.cardTitle}>
          {t('ux.compareMenu.change.title')}
        </h2>
        <p className={styles.cardSub}>{t('ux.compareMenu.change.sub')}</p>
        <ul className={styles.presets}>
          {presets.map(([field, to, key, value]) => (
            <li key={field}>
              <Link to={`/simulate/policy?${new URLSearchParams({ tab: 'compose', case: ATTACK, field, to }).toString()}`}>
                <Icon name="arrow-right" size="sm" />
                {t(key, { n: value })}
              </Link>
            </li>
          ))}
        </ul>
        <p className={styles.muted}>{t('ux.compareMenu.change.note')}</p>
      </section>
    </div>
  );
}

function useSide(runId: string | null) {
  const score = useRunScore(runId, 'compare', 1);
  const received = useReceived(runId, 1);
  return { score: score.data ?? null, received: received.data ?? null };
}

function SideRow({
  name,
  own,
  runId,
  side,
  control,
}: {
  readonly name: string;
  readonly own: boolean;
  readonly runId: string | null;
  readonly side: ReturnType<typeof useSide>;
  readonly control: 'C1' | 'B';
}) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const now = (dimension: string) => side.received?.usualVsNow.find((row) => row.dimension === dimension)?.now ?? null;
  const rule = side.score?.business[control] ?? null;
  const contexa = side.score?.business.D ?? null;
  const ruleGrade = evalOf(rule?.result);
  return (
    <tr>
      <th scope="row">
        <b>{name}</b>
        <span className={styles.sub}>
          {runId ? <Link to={`/runs/${encodeURIComponent(runId)}`}>{runId}</Link> : '—'} ·{' '}
          {t(own ? 'ux.runs.source.own' : 'ux.runs.source.public')}
        </span>
      </th>
      <td>
        {[now('accessHour') ? t('ux.compareMenu.hour', { h: now('accessHour') }) : null, now('size'), deviceWords(now('device'))]
          .filter(Boolean)
          .join(' · ')}
      </td>
      <td>
        {rule ? (
          <span className={styles.cell}>
            {ruleGrade ? <EvalBadge result={ruleGrade} /> : null}
            <span className={styles.muted}>{t('ux.compareMenu.exported', { n: n(rule.exposedItems) })}</span>
          </span>
        ) : (
          '…'
        )}
      </td>
      <td>
        {side.score ? (
          <span className={styles.cell}>
            <VerdictBadge verdict={verdictOf(decisionOf(side.score).action)} />
            <span className={styles.muted}>{t('ux.compareMenu.exported', { n: n(contexa?.exposedItems ?? 0) })}</span>
          </span>
        ) : (
          '…'
        )}
      </td>
    </tr>
  );
}

/** 조건 변경 실험 (옛 7-2): the visitor's composed runs, and the way to compose another (ST-52). */
function ChangeTab() {
  const { t } = useTranslation();
  const visitor = useVisitor();
  const recent = useRecentLabRuns();
  if (!visitor.isSuccess || recent.isPending) {
    return <Loading rows={4} />;
  }
  const runs = [...(recent.data ?? [])].reverse();
  return (
    <section className={styles.card} aria-labelledby="compare-mine">
      <h2 id="compare-mine" className={styles.cardTitle}>
        {t('ux.compareMenu.mine.title')}
      </h2>
      <p className={styles.cardSub}>{t('ux.compareMenu.mine.sub')}</p>
      {runs.length === 0 ? (
        <Note>{t('ux.compareMenu.mine.none')}</Note>
      ) : (
        <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
          <table className={styles.table}>
            <caption className="ux-sr-only">{t('ux.compareMenu.mine.title')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.runs.col.at')}</th>
                <th scope="col">{t('ux.runs.col.scenario')}</th>
                <th scope="col">{t('ux.compareMenu.mine.changed')}</th>
                <th scope="col">{t('ux.compareMenu.mine.call')}</th>
                <th scope="col">{t('ux.compareMenu.col.run')}</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.runId}>
                  <td>{formatUtc(run.composedAt)}</td>
                  <th scope="row">{run.caseKey}</th>
                  <td>
                    {run.designed
                      ? t('ux.compareMenu.mine.designed')
                      : run.changed.map((key) => t(`ux.cond.field.${key}`, { defaultValue: key })).join(' · ')}
                    {run.designed ? null : <LineDelta runId={run.runId} />}
                  </td>
                  <td>{run.call ? t(`ux.policy.send.call.${run.call}`, { defaultValue: run.call }) : '—'}</td>
                  <td>
                    <Link to={`/runs/${encodeURIComponent(run.runId)}`}>{run.runId}</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ButtonLink to="/simulate/policy?tab=compose" variant="primary" iconAfter="arrow-right">
        {t('ux.compareMenu.mine.compose')}
      </ButtonLink>
    </section>
  );
}

/** The prompt lines the change changed (옛 7-2): the portal's comparison of the two sealed prompts, read once opened. */
function LineDelta({ runId }: { readonly runId: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <details className={styles.more} onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary>{t('ux.compareMenu.mine.delta')}</summary>
      {open ? <LineDeltaBody runId={runId} /> : null}
    </details>
  );
}

function LineDeltaBody({ runId }: { readonly runId: string }) {
  const { t, i18n } = useTranslation();
  const delta = useLabDelta(runId);
  if (delta.isPending) {
    return <Loading rows={2} />;
  }
  if (!delta.data) {
    return <Note tone="warn">{t('ux.compareMenu.mine.deltaFailed')}</Note>;
  }
  // The first request's comparison, as the old screen showed it; a step the server did not compare says why.
  const step = delta.data.steps.find((candidate) => candidate.stepNo === 1) ?? null;
  const why = delta.data.available ? (step?.notCompared ?? null) : delta.data.reason;
  if (step === null || why !== null) {
    return <p className={styles.muted}>{t('ux.compareMenu.mine.deltaUnavailable', { reason: why ?? '—' })}</p>;
  }
  return (
    <div className={styles.delta}>
      {step.changed.length === 0 ? <p className={styles.muted}>{t('ux.compareMenu.mine.deltaNone')}</p> : null}
      {step.changed.map((line) => (
        <div key={line.label} className={styles.diffPair}>
          <code data-side="before" lang="en">
            - {line.label}: {line.before.join(', ')}
          </code>
          <code data-side="after" lang="en">
            + {line.label}: {line.after.join(', ')}
          </code>
        </div>
      ))}
      {step.unchangedLines != null ? (
        <p className={styles.muted}>
          {t('ux.compareMenu.mine.unchanged', { n: formatNumber(step.unchangedLines, i18n.language) })}
        </p>
      ) : null}
    </div>
  );
}

const CONTROLS = ['C1', 'C2', 'D'] as const;
const ORDER: readonly string[] = ['STOPPED', 'PARTLY_STOPPED', 'PASSED_AFTER_CHECK', 'PASSED', 'HALTED', 'MISSED'];

/** 반복 측정 결과 (옛 7-3): every measured run as a dot per control, attacks and normal work apart (ST-53). */
function RunsTab() {
  const { t, i18n } = useTranslation();
  const benchmark = useBenchmark(null);
  const n = (value: number) => formatNumber(value, i18n.language);
  if (benchmark.isPending) {
    return <Loading rows={6} />;
  }
  if (!benchmark.data) {
    return <ErrorState onRetry={() => void benchmark.refetch()}>{t('ux.compareMenu.runs.failed')}</ErrorState>;
  }
  const data = benchmark.data;
  const dots = (classification: string, control: string) =>
    data.cases
      .filter((found) => found.classification === classification)
      .flatMap((found) =>
        Object.entries(found.runResults ?? {}).flatMap(([runId, results]) => {
          const result = results[control];
          return result ? [{ runId, result, key: found.key }] : [];
        }),
      )
      .sort((a, b) => ORDER.indexOf(a.result) - ORDER.indexOf(b.result));
  const scoreOf = (control: string) => data.controls.find((found) => found.control === control) ?? null;
  return (
    <section className={styles.card} aria-labelledby="compare-runs">
      <h2 id="compare-runs" className={styles.cardTitle}>
        {t('ux.compareMenu.runs.title')}
      </h2>
      <p className={styles.cardSub}>
        {t('ux.compareMenu.runs.sub', {
          runs: n(data.scope.runs),
          cases: n(data.scope.cases),
          attacks: n(data.scope.attackRuns),
          normals: n(data.scope.normalRuns),
        })}
      </p>
      {/* The attack and normal columns share the width by their runs, so both wrap at the same density. */}
      <div
        className={styles.dotsTable}
        style={
          {
            '--attack-share': `${Math.max(data.scope.attackRuns, 1)}fr`,
            '--normal-share': `${Math.max(data.scope.normalRuns, 1)}fr`,
          } as CSSProperties
        }
      >
        <span />
        <span className={styles.dotsHead}>{t('ux.compareMenu.runs.attacks', { n: n(data.scope.attackRuns) })}</span>
        <span className={styles.dotsHead}>{t('ux.compareMenu.runs.normals', { n: n(data.scope.normalRuns) })}</span>
        <span className={styles.dotsHead}>{t('ux.compareMenu.runs.totals')}</span>
        {CONTROLS.map((control) => {
          const score = scoreOf(control);
          return (
            <div key={control} className={styles.dotsRow} data-contexa={control === 'D' || undefined}>
              <span className={styles.dotsName}>{t(`ux.control.${control}`)}</span>
              {(['THREAT', 'NORMAL'] as const).map((kind) => (
                <ul key={kind} className={styles.dots} aria-label={`${t(`ux.control.${control}`)} · ${t(`ux.runs.kind.${kind}`)}`}>
                  {dots(kind, control).map((dot) => {
                    const graded = evalOf(dot.result as CaseResult);
                    return (
                      <li key={dot.runId}>
                        <Link
                          to={`/runs/${encodeURIComponent(dot.runId)}`}
                          className={styles.dot}
                          data-tone={graded ? EVAL_TONES[graded] : 'none'}
                          data-eval={graded ?? undefined}
                          aria-label={t('ux.compareMenu.runs.dot', {
                            run: dot.runId,
                            key: dot.key,
                            result: graded ? t(`ux.runs.result.${graded}`) : dot.result,
                          })}
                          title={`${dot.key} · ${dot.runId}`}
                        />
                      </li>
                    );
                  })}
                </ul>
              ))}
              <span className={styles.dotsTotal}>
                {score
                  ? t('ux.compareMenu.runs.total', { missed: n(score.missed), blocked: n(score.falseBlock.hits) })
                  : '—'}
              </span>
            </div>
          );
        })}
      </div>
      <ul className={styles.legend}>
        {(['correct', 'normal', 'afterCheck', 'partial', 'missed', 'falsePositive'] as const).map((graded) => (
          <li key={graded}>
            <i className={styles.dot} data-tone={EVAL_TONES[graded]} data-eval={graded} aria-hidden="true" />
            {t(`ux.runs.result.${graded}`)}
          </li>
        ))}
      </ul>
      {data.scope.otherRuns > 0 ? <Note>{t('ux.compareMenu.runs.others', { n: n(data.scope.otherRuns) })}</Note> : null}
      <p className={styles.muted}>
        <Badge tone="line">{t('ux.compareMenu.runs.measured')}</Badge>{' '}
        {data.scope.protocols.at(-1)?.finishedAt ? formatUtc(data.scope.protocols.at(-1)?.finishedAt ?? '').slice(0, 10) : ''}{' '}
        <CodeChip value={data.scope.protocols.at(-1)?.protocolId ?? '—'} />
      </p>
    </section>
  );
}
