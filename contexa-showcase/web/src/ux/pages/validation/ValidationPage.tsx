import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import type { ReactNode } from 'react';
import { useBenchmark, type BenchmarkView, type ControlScore } from '../../../api/benchmark';
import { useStats } from '../../../api/queries';
import { usePublicSettings, type PublicSettingsView } from '../../../api/settings';
import { formatNumber, formatUtc } from '../../format';
import {
  Badge,
  ButtonLink,
  Card,
  EmptyState,
  ErrorState,
  Field,
  Kpi,
  Loading,
  Note,
  PageHead,
  Select,
  TabPanel,
  Tabs,
} from '../../ui';
import {
  CONTROLS,
  fewestExistingMisses,
  scoreOf,
  sentPerCase,
  sharedNormals,
  suiteOf,
  useValidationSetting,
} from '../../validation/shapes';
import { AgentTab, LimitsTab, MethodTab } from './OtherTabs';
import QualityTab from './QualityTab';
import ScenariosTab from './ScenariosTab';
import { useReasonMatch, useSegments } from '../../validation/hooks';
import { DotLegend, RateMeter, RateText, ResultBar, ResultLegend, RunDots } from './ValidationParts';
import styles from './Validation.module.css';
import { breakable } from '../../ui/breakable';

const TABS = ['summary', 'controls', 'scenarios', 'quality', 'agent', 'limits', 'method'] as const;
type TabId = (typeof TABS)[number];

/**
 * The scenario validation (기획안 7.11, DEC-49 ~ DEC-53): the demo's own scenarios sent repeatedly to the five
 * controls, as the portal counted them. It says first that it is the team's own measurement, not an external standard
 * result; every tab reads the chosen measurement setting (`?setting=`), the latest by default.
 */
export default function ValidationPage() {
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const setting = useValidationSetting();
  const benchmark = useBenchmark(setting);
  const view = benchmark.data ?? null;
  const tab: TabId = TABS.includes(params.get('tab') as TabId) ? (params.get('tab') as TabId) : 'summary';
  const spec = view?.spec ?? null;
  return (
    <>
      <PageHead
        title={t('ux.validation.title')}
        desc={
          view && spec
            ? t('ux.validation.desc', { cases: formatNumber(view.scope.cases, i18n.language) })
            : t('ux.validation.descPlain')
        }
        actions={
          <ButtonLink to="/benchmarks" variant="secondary" icon="clipboard-check">
            {t('ux.validation.toStandard')}
          </ButtonLink>
        }
      />
      {view && spec ? (
        <Note icon="flask-conical">
          <b>{t('ux.validation.nature.title')}</b>{' '}
          {t('ux.validation.nature.text', {
            from: formatUtc(spec.firstRunAt).slice(0, 10),
            to: formatUtc(spec.lastRunAt).slice(0, 10),
            build: spec.codeCommit,
            bundles: (spec.promptBundles ?? []).join(', ') || '—',
            repeat: sentPerCase(view),
          })}{' '}
          <BuildBadge measured={spec.codeCommit} />
        </Note>
      ) : null}
      <Tabs
        idBase="validation"
        label={t('ux.validation.tabs')}
        value={tab}
        onChange={(id) => {
          const next = new URLSearchParams();
          next.set('tab', id);
          if (setting) {
            next.set('setting', setting);
          }
          setParams(next, { replace: true });
        }}
        items={TABS.map((id) => ({ id, label: t(`ux.validation.tab.${id}`) }))}
      />
      <TabPanel idBase="validation" id={tab}>
        {tab === 'agent' ? (
          <AgentTab />
        ) : benchmark.isPending ? (
          <Loading rows={8} />
        ) : !view ? (
          // ST-54: the measurement could not be read.
          <ErrorState onRetry={() => void benchmark.refetch()}>{t('ux.validation.failed')}</ErrorState>
        ) : !spec ? (
          // ST-55: no measurement yet.
          <EmptyState>{t('ux.validation.empty')}</EmptyState>
        ) : tab === 'summary' ? (
          <SummaryTab view={view} />
        ) : tab === 'controls' ? (
          <ControlsTab view={view} />
        ) : tab === 'scenarios' ? (
          <ScenariosTab view={view} />
        ) : tab === 'quality' ? (
          <QualityTab view={view} />
        ) : tab === 'limits' ? (
          <LimitsTab view={view} />
        ) : (
          <MethodTab view={view} />
        )}
      </TabPanel>
    </>
  );
}

/**
 * Whether the measurement is the current build's (UC-14): its code commit against the one of the latest counted run
 * (the engine running now). Nothing is said while the operations record is not read.
 */
function BuildBadge({ measured }: { readonly measured: string }) {
  const { t } = useTranslation();
  const stats = useStats();
  const running = stats.data?.spec?.codeCommit ?? null;
  if (running === null) {
    return null;
  }
  return running === measured ? (
    <Badge tone="allow">{t('ux.validation.nature.current')}</Badge>
  ) : (
    <Badge tone="line">{t('ux.validation.nature.remeasure')}</Badge>
  );
}

function SummaryTab({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const contexa = scoreOf(view.controls, 'D');
  const fewest = fewestExistingMisses(view.controls);
  const segments = useSegments();
  const reasons = useReasonMatch(view.spec?.settingHash ?? null);
  const proof = view.blindSpot ?? null;
  const charted = proof !== null && proof.totals !== undefined && (proof.pairs ?? []).length > 0;
  return (
    <div className={styles.stack}>
      <div className={styles.kpis}>
        <Kpi
          icon="shield-x"
          label={t('ux.validation.kpi.attacks')}
          value={n(view.scope.attackRuns)}
          unit={t('ux.validation.unit.runs')}
          foot={t('ux.validation.kpi.attacksFoot', {
            contexa: n(contexa?.missed ?? 0),
            fewest: fewest === null ? '—' : n(fewest),
          })}
        />
        <Kpi
          icon="user-round-check"
          label={t('ux.validation.kpi.normals')}
          value={n(view.scope.normalRuns)}
          unit={t('ux.validation.unit.runs')}
          foot={t('ux.validation.kpi.normalsFoot', {
            blocked: n(contexa?.falseBlock.hits ?? 0),
            checked: n(contexa?.friction.hits ?? 0),
          })}
        />
        <Kpi
          icon="circle-help"
          label={t('ux.validation.kpi.open')}
          value={n(view.scope.otherRuns)}
          unit={t('ux.validation.unit.runs')}
          foot={t('ux.validation.kpi.openFoot')}
        />
      </div>
      <p className={styles.line}>
        {t('ux.validation.scope', {
          cases: n(view.scope.cases),
          attacks: n(view.caseCounts.THREAT),
          normals: n(view.caseCounts.NORMAL),
          open: n(view.caseCounts.UNCERTAIN),
          repeat: sentPerCase(view),
          runs: n(view.scope.runs),
        })}
        {view.engine ? ` ${t('ux.validation.decisions', { n: n(view.engine.decisions) })}` : ''}
      </p>
      <Card title={t('ux.validation.byControl.title')} sub={t('ux.validation.byControl.sub')} flush>
        <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
          <table className={styles.table} data-stack>
            <caption className="ux-sr-only">{t('ux.validation.byControl.title')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.validation.col.control')}</th>
                <th scope="col">{t('ux.validation.col.attacks', { n: n(view.scope.attackRuns) })}</th>
                <th scope="col">{t('ux.validation.col.normals', { n: n(view.scope.normalRuns) })}</th>
                <th scope="col">{t('ux.validation.col.wrong')}</th>
              </tr>
            </thead>
            <tbody>
              {CONTROLS.map((control) => {
                const score = scoreOf(view.controls, control);
                return score ? (
                  <tr key={control} data-contexa={control === 'D' || undefined}>
                    <th scope="row">{t(`ux.control.${control}`)}</th>
                    <td data-k={t('ux.validation.col.attacks', { n: n(view.scope.attackRuns) })}>
                      <ResultBar
                        label={t('ux.validation.col.attacks', { n: n(view.scope.attackRuns) })}
                        segments={segments.attack(score)}
                      />
                    </td>
                    <td data-k={t('ux.validation.col.normals', { n: n(view.scope.normalRuns) })}>
                      <ResultBar
                        label={t('ux.validation.col.normals', { n: n(view.scope.normalRuns) })}
                        segments={segments.normal(score)}
                      />
                    </td>
                    <td data-k={t('ux.validation.col.wrong')}>
                      {t('ux.validation.wrongValue', {
                        missed: n(score.missed),
                        blocked: n(score.falseBlock.hits),
                      })}
                    </td>
                  </tr>
                ) : null;
              })}
            </tbody>
          </table>
        </div>
        <div className={styles.cardFoot}>
          <ResultLegend items={segments.legend} />
          <p className={styles.note}>
            {t('ux.validation.byControl.note', {
              partial: n(contexa?.partlyStopped ?? 0),
            })}
          </p>
        </div>
      </Card>
      {charted && proof.totals ? (
        <>
          <Card
            title={t('ux.validation.proof.title')}
            sub={t('ux.validation.proof.sub', { n: n(proof.pairs?.length ?? 0) })}
          >
            <ol className={styles.proof}>
              {(
                [
                  [
                    'g1',
                    t('ux.validation.proof.ofRuns', {
                      n: n(proof.totals.attackAllPassed),
                      of: n(proof.totals.attackRuns),
                    }),
                  ],
                  [
                    'g2',
                    t('ux.validation.proof.ofRuns', {
                      n: n(proof.totals.normalAllPassed),
                      of: n(proof.totals.normalRuns),
                    }),
                  ],
                  [
                    'g3',
                    t('ux.validation.proof.g3Value', {
                      stopped: n(proof.totals.contexaStopped),
                      fully: n(proof.totals.contexaFullyStopped),
                      attacks: n(proof.totals.attackAllPassed),
                      passed: n(proof.totals.contexaPassed),
                      normals: n(proof.totals.normalAllPassed),
                    }),
                  ],
                  [
                    'g4',
                    view.engine?.agreement && view.engine.agreement.modelAnswered > 0
                      ? t('ux.validation.proof.g4Value', {
                          as: n(view.engine.agreement.asAnswered),
                          answered: n(view.engine.agreement.modelAnswered),
                          held: n(view.engine.agreement.held),
                        })
                      : null,
                  ],
                  [
                    'g5',
                    reasons && reasons.total > 0
                      ? t('ux.validation.proof.ofReasons', { n: n(reasons.hits), of: n(reasons.total) })
                      : null,
                  ],
                ] as const
              ).map(([id, value], index) => (
                <li key={id} className={styles.proofLine}>
                  <span className={styles.proofId}>{t('ux.validation.proof.label', { n: index + 1 })}</span>
                  <span>{t(`ux.validation.proof.${id}`)}</span>
                  <b className={styles.proofValue}>{value ?? t('ux.validation.proof.none')}</b>
                </li>
              ))}
            </ol>
          </Card>
          <Pairs view={view} />
        </>
      ) : (
        <ProofTables view={view} />
      )}
    </div>
  );
}

/** Contexa's results in a case's counted runs, as the portal counted them: "적중 4 · 미탐 1". */
function useContexaWords() {
  const { t, i18n } = useTranslation();
  return (contexa: Readonly<Record<string, number>>) =>
    Object.entries(contexa)
      .filter(([, count]) => count > 0)
      .map(
        ([result, count]) =>
          `${t(`ux.validation.result.${result}`, { defaultValue: result })} ${formatNumber(count, i18n.language)}`,
      )
      .join(' · ');
}

/** Each designed blind-spot attack over the normal work of the same conditions, a dot per run every existing control let through. */
function Pairs({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const words = useContexaWords();
  const proof = view.blindSpot ?? null;
  if (!proof) {
    return null;
  }
  const nameOf = (key: string) =>
    view.cases.find((row) => row.key === key)?.title[i18n.language === 'ko' ? 'ko' : 'en'] ?? key;
  const attacks = new Map(proof.attacks.map((row) => [row.key, row]));
  const normals = new Map(proof.normals.map((row) => [row.key, row]));
  const pairs = proof.pairs ?? [];
  const paired = new Set(pairs.map((pair) => pair.attack));
  const alone = proof.attacks.filter((row) => !paired.has(row.key));
  const shared = new Set(sharedNormals(proof));
  const line = (key: string, side: 'attack' | 'normal') => {
    const row = side === 'attack' ? attacks.get(key) : normals.get(key);
    if (!row) {
      return null;
    }
    return (
      <div className={styles.pairLine} data-side={side}>
        <span className={styles.pairName}>
          <Badge tone="line">{t(`ux.validation.pair.${side}`)}</Badge>
          {nameOf(row.key)} <span className={styles.sub}>{row.key}</span>
        </span>
        <RunDots
          label={t('ux.validation.pair.dots', { name: nameOf(row.key) })}
          runs={row.passedRuns ?? []}
        />
        <span className={styles.sub}>
          {t('ux.validation.pair.value', { passed: n(row.allPassed), runs: n(row.runs) })}
          {row.allPassed > 0 ? ` · Contexa ${words(row.contexa)}` : ''}
        </span>
        {side === 'normal' && shared.has(row.key) ? (
          <span className={styles.sub}>{t('ux.validation.pair.shared')}</span>
        ) : null}
      </div>
    );
  };
  const groups = [...new Set(pairs.map((pair) => pair.group))];
  return (
    <Card title={t('ux.validation.pairs.title')} sub={t('ux.validation.pairs.sub')}>
      <div className={styles.pairs}>
        <DotLegend />
        {groups.map((group) => (
          <section
            key={group}
            className={styles.pairGroup}
            aria-label={t(`ux.validation.group.${group}`, { defaultValue: group })}
          >
            <h3 className={styles.groupTitle}>
              {t(`ux.validation.group.${group}`, { defaultValue: group })}
            </h3>
            {pairs
              .filter((pair) => pair.group === group)
              .map((pair) => (
                <div key={`${pair.attack}-${pair.normal ?? ''}`} className={styles.pair}>
                  {line(pair.attack, 'attack')}
                  {pair.normal ? line(pair.normal, 'normal') : null}
                </div>
              ))}
          </section>
        ))}
        {alone.length > 0 ? (
          <section className={styles.pairGroup} aria-label={t('ux.validation.group.alone')}>
            <h3 className={styles.groupTitle}>{t('ux.validation.group.alone')}</h3>
            {alone.map((row) => (
              <div key={row.key} className={styles.pair}>
                {line(row.key, 'attack')}
              </div>
            ))}
          </section>
        ) : null}
      </div>
    </Card>
  );
}

/** An older setting without the designed pairs: the attacks and the normal work every existing control let through (ST-66). */
function ProofTables({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const words = useContexaWords();
  const proof = view.blindSpot ?? null;
  if (!proof) {
    return null;
  }
  const table = (side: 'attack' | 'normal', rows: typeof proof.attacks) => (
    <Card key={side} title={t(`ux.validation.proofTable.${side}`)} flush>
      {rows.length === 0 ? (
        <p className={styles.padded}>{t('ux.validation.proofTable.none')}</p>
      ) : (
        <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
          <table className={styles.table} data-stack>
            <caption className="ux-sr-only">{t(`ux.validation.proofTable.${side}`)}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.validation.col.case')}</th>
                <th scope="col">{t('ux.validation.proofTable.allPassed')}</th>
                <th scope="col">Contexa</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.key}>
                  <th scope="row">{row.key}</th>
                  <td
                    data-k={t('ux.validation.proofTable.allPassed')}
                  >{`${n(row.allPassed)} / ${n(row.runs)}`}</td>
                  <td data-k="Contexa">{words(row.contexa) || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
  return (
    <div className={styles.split}>
      {table('attack', proof.attacks)}
      {table('normal', proof.normals)}
    </div>
  );
}

const QUESTIONS = ['mostStopped', 'mostFalseBlock', 'cleanMostStopped'] as const;

function ControlsTab({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const n = (value: number) => formatNumber(value, i18n.language);
  const { suite, controls, conclusions } = suiteOf(view, params.get('suite'));
  const contexa = scoreOf(controls, 'D');
  const set = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) {
      next.set(key, value);
    } else {
      next.delete(key);
    }
    setParams(next, { replace: true });
  };
  const marked = QUESTIONS.some((question) => conclusions[question].controls.includes('C2'));
  const chosen = scoreOf(controls, params.get('control') ?? 'D') ?? contexa;
  return (
    <div className={styles.stack}>
      {view.suites.length > 0 ? (
        <div className={styles.filters}>
          <Field label={t('ux.validation.suite.label')}>
            {(props) => (
              <Select
                {...props}
                compact
                value={suite?.suite ?? ''}
                onChange={(event) => set('suite', event.target.value || null)}
              >
                <option value="">{t('ux.validation.suite.all')}</option>
                {view.suites.map((candidate) => (
                  <option key={candidate.suite} value={candidate.suite}>
                    {t(`ux.validation.suite.${candidate.suite}`, { defaultValue: candidate.suite })}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
      ) : null}
      <Card
        title={t('ux.validation.rates.title')}
        sub={
          contexa
            ? t('ux.validation.rates.sub', {
                attacks: n(contexa.stoppedAny.total),
                normals: n(contexa.falseBlock.total),
              })
            : undefined
        }
        flush
      >
        <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
          <table className={styles.table} data-stack>
            <caption className="ux-sr-only">{t('ux.validation.rates.title')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.validation.col.control')}</th>
                <th scope="col">{t('ux.validation.col.detection')}</th>
                <th scope="col">{t('ux.validation.col.falsePositive')}</th>
                <th scope="col">{t('ux.validation.col.missed')}</th>
                <th scope="col">{t('ux.validation.col.partial')}</th>
                <th scope="col">{t('ux.validation.col.checked')}</th>
              </tr>
            </thead>
            <tbody>
              {CONTROLS.map((control) => {
                const score = scoreOf(controls, control);
                if (!score) {
                  return null;
                }
                const empty = score.stoppedAny.total === 0 && score.falseBlock.total === 0;
                return (
                  <tr key={control} data-contexa={control === 'D' || undefined}>
                    <th scope="row">
                      {t(`ux.control.${control}`)}
                      {control === 'C2' ? ' *' : ''}
                    </th>
                    {empty ? (
                      // ST-64: no run of the chosen group reached this control.
                      <td colSpan={5} data-k={t('ux.validation.col.detection')}>
                        {t('ux.validation.rates.empty')}
                      </td>
                    ) : (
                      <>
                        <td data-k={t('ux.validation.col.detection')}>
                          <RateText rate={score.stoppedAny} strong={control === 'D'} />
                          <RateMeter rate={score.stoppedAny} contexa={control === 'D'} />
                        </td>
                        <td data-k={t('ux.validation.col.falsePositive')}>
                          <RateText rate={score.falseBlock} strong={control === 'D'} />
                          <RateMeter rate={score.falseBlock} contexa={control === 'D'} />
                        </td>
                        <td data-k={t('ux.validation.col.missed')}>{n(score.missed)}</td>
                        <td data-k={t('ux.validation.col.partial')}>{n(score.partlyStopped)}</td>
                        <td data-k={t('ux.validation.col.checked')}>{n(score.friction.hits)}</td>
                      </>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className={styles.cardFoot}>
          <p className={styles.note}>{t('ux.validation.rates.read')}</p>
          {suite === null && contexa && view.judgmentTiming.STATIC_REFUSAL > 0 ? (
            <p className={styles.note}>
              {t('ux.validation.rates.static', {
                hits: n(contexa.stoppedAny.hits),
                total: n(contexa.stoppedAny.total),
                count: view.judgmentTiming.STATIC_REFUSAL,
                n: n(view.judgmentTiming.STATIC_REFUSAL),
              })}
            </p>
          ) : null}
          <p className={styles.note}>{t('ux.validation.footnote')}</p>
          <Link to="/compare?tab=runs" className={styles.textLink}>
            {t('ux.validation.rates.dots')}
          </Link>
        </div>
      </Card>
      <Card title={t('ux.validation.answers.title')}>
        <ul className={styles.answers}>
          {QUESTIONS.map((question) => {
            const pick = conclusions[question];
            return (
              <li key={question}>
                <span className={styles.sub}>{t(`ux.validation.answers.${question}`)}</span>
                <b>
                  {pick.controls.length > 0
                    ? pick.controls
                        .map((control) => `${t(`ux.control.${control}`)}${control === 'C2' ? ' *' : ''}`)
                        .join(' · ')
                    : t(`ux.validation.answers.none.${question}`)}
                </b>
                {pick.controls.length > 0 ? (
                  <span className={styles.sub}>
                    {t(`ux.validation.answers.value.${question}`, {
                      hits: n(pick.hits),
                      total: n(pick.total),
                    })}
                  </span>
                ) : null}
              </li>
            );
          })}
        </ul>
        {marked ? <p className={styles.note}>{t('ux.validation.footnote')}</p> : null}
      </Card>
      <ScoresCard controls={controls} />
      {chosen ? (
        <ControlDetail score={chosen} controls={controls} onChoose={(control) => set('control', control)} />
      ) : null}
    </div>
  );
}

const SCORES = ['stopped', 'stoppedAny', 'notBlocked'] as const;

/** The three scores of every control, as the server counted them, and how to read them. */
function ScoresCard({ controls }: { readonly controls: readonly ControlScore[] }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  return (
    <Card title={t('ux.validation.scores.title')} flush>
      <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
        <table className={styles.table} data-stack>
          <caption className="ux-sr-only">{t('ux.validation.scores.title')}</caption>
          <thead>
            <tr>
              <th scope="col">{t('ux.validation.col.control')}</th>
              {SCORES.map((score) => (
                <th key={score} scope="col">
                  {t(`ux.validation.score.${score}`)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {CONTROLS.map((control) => {
              const score = scoreOf(controls, control);
              return score ? (
                <tr key={control} data-contexa={control === 'D' || undefined}>
                  <th scope="row">
                    {t(`ux.control.${control}`)}
                    {control === 'C2' ? ' *' : ''}
                  </th>
                  {SCORES.map((name) => (
                    <td key={name} data-k={t(`ux.validation.score.${name}`)}>
                      <RateText rate={score[name]} strong={control === 'D'} />
                      {name === 'notBlocked' && score.friction.hits > 0 ? (
                        <span className={styles.sub}>
                          {t('ux.validation.score.withCheck', { n: n(score.friction.hits) })}
                        </span>
                      ) : null}
                    </td>
                  ))}
                </tr>
              ) : null;
            })}
          </tbody>
        </table>
      </div>
      <div className={styles.cardFoot}>
        <ul className={styles.notes}>
          {(['better', 'preliminary', 'same'] as const).map((item) => (
            <li key={item}>{t(`ux.validation.scores.read.${item}`)}</li>
          ))}
        </ul>
      </div>
    </Card>
  );
}

/** One control in detail: its scores with their ranges, what it handled wrong, and its settings in this demo. */
function ControlDetail({
  score,
  controls,
  onChoose,
}: {
  readonly score: ControlScore;
  readonly controls: readonly ControlScore[];
  readonly onChoose: (control: string) => void;
}) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const settings = usePublicSettings();
  return (
    <Card
      title={t('ux.validation.detail.title', { name: t(`ux.control.${score.control}`) })}
      actions={
        <Field label={t('ux.validation.detail.choose')}>
          {(props) => (
            <Select
              {...props}
              compact
              value={score.control}
              onChange={(event) => onChoose(event.target.value)}
            >
              {CONTROLS.filter((control) => controls.some((candidate) => candidate.control === control)).map(
                (control) => (
                  <option key={control} value={control}>
                    {t(`ux.control.${control}`)}
                  </option>
                ),
              )}
            </Select>
          )}
        </Field>
      }
    >
      <div className={styles.detailGrid}>
        <dl className={styles.kv}>
          {SCORES.map((name) => (
            <div key={name}>
              <dt>{t(`ux.validation.score.${name}`)}</dt>
              <dd>
                <RateText rate={score[name]} strong />
              </dd>
            </div>
          ))}
        </dl>
        <div>
          <h3 className={styles.groupTitle}>{t('ux.validation.detail.wrong')}</h3>
          <ul className={styles.notes}>
            <li>{t('ux.validation.detail.missed', { n: n(score.missed) })}</li>
            <li>{t('ux.validation.detail.partly', { n: n(score.partlyStopped) })}</li>
            <li>{t('ux.validation.detail.falseBlock', { n: n(score.falseBlock.hits) })}</li>
            <li>
              {t('ux.validation.detail.unresolved', {
                attack: n(score.attackUnresolved),
                normal: n(score.normalUnresolved),
              })}
            </li>
          </ul>
        </div>
        <div>
          <h3 className={styles.groupTitle}>{t('ux.validation.detail.settings')}</h3>
          {settings.data ? (
            <ControlSettings control={score.control} settings={settings.data} />
          ) : settings.isError ? (
            <p className={styles.note}>{t('ux.validation.detail.settingsFailed')}</p>
          ) : (
            <Loading rows={2} />
          )}
        </div>
      </div>
    </Card>
  );
}

/** A control's settings as the running demo publishes them (`/api/settings`); the screen sets none of them. */
function ControlSettings({
  control,
  settings,
}: {
  readonly control: string;
  readonly settings: PublicSettingsView;
}) {
  const { t, i18n } = useTranslation();
  const none = t('ux.validation.set.none');
  const days = (value: number | null) =>
    value === null ? none : t('ux.validation.set.days', { n: formatNumber(value, i18n.language) });
  const items = (value: number | null) =>
    value === null ? none : t('ux.validation.set.items', { n: formatNumber(value, i18n.language) });
  const yes = (value: boolean | null) =>
    value === null ? none : t(value ? 'ux.validation.set.yes' : 'ux.validation.set.no');
  const code = (value: string | null) =>
    value === null ? none : <code className={styles.code}>{breakable(value)}</code>;
  const rows: [string, ReactNode][] =
    control === 'A'
      ? [
          [t('ux.validation.set.A.image'), code(settings.waf.image)],
          [t('ux.validation.set.A.ruleSet'), code(settings.waf.ruleSet)],
        ]
      : control === 'B'
        ? [
            [
              t('ux.validation.set.B.rules', { n: settings.permission.roleRules.length }),
              <ul key="r" className={styles.codeList}>
                {settings.permission.roleRules.map((rule) => (
                  <li key={rule}>
                    <code className={styles.code}>{breakable(rule)}</code>
                  </li>
                ))}
              </ul>,
            ],
          ]
        : control === 'C1'
          ? [
              [
                t('ux.validation.set.C1.night'),
                settings.threshold.nightStart && settings.threshold.nightEnd
                  ? `${settings.threshold.nightStart} ~ ${settings.threshold.nightEnd}`
                  : none,
              ],
              [t('ux.validation.set.C1.volume'), items(settings.threshold.volumeLimit)],
              [t('ux.validation.set.C1.dormant'), days(settings.threshold.dormantWindowDays)],
            ]
          : control === 'C2'
            ? [
                [t('ux.validation.set.C2.policy'), code(settings.businessRecord.exportPolicyKey)],
                [t('ux.validation.set.C2.assigned'), items(settings.businessRecord.assignedExportLimit)],
                [t('ux.validation.set.C2.ticket'), yes(settings.businessRecord.ticketAndOncallExempt)],
                [t('ux.validation.set.C2.history'), days(settings.businessRecord.historyWindowDays)],
                [
                  t('ux.validation.set.C2.exportHistory'),
                  days(settings.businessRecord.exportHistoryWindowDays),
                ],
                [
                  t('ux.validation.set.C2.access'),
                  <ul key="a" className={styles.codeList}>
                    {settings.businessRecord.accessPolicies.map((policy) => (
                      <li key={policy.policyKey ?? ''}>
                        <code className={styles.code}>{breakable(policy.policyKey ?? none)}</code>{' '}
                        {t('ux.validation.set.C2.accessValue', {
                          manager: yes(policy.accountManagerExempt),
                          assigned: yes(policy.assignedExempt),
                          days: days(policy.recentWorkDays),
                        })}
                      </li>
                    ))}
                  </ul>,
                ],
              ]
            : [
                ...(settings.engine.layer1Model && settings.engine.layer2Model
                  ? ([
                      [t('ux.validation.set.D.layer1'), code(settings.engine.layer1Model)],
                      [t('ux.validation.set.D.layer2'), code(settings.engine.layer2Model)],
                    ] as [string, ReactNode][])
                  : ([[t('ux.validation.set.D.model'), code(settings.engine.chatModel)]] as [
                      string,
                      ReactNode,
                    ][])),
                [
                  t('ux.validation.set.D.mode'),
                  settings.engine.effectiveMode
                    ? t(`ux.validation.set.D.mode.${settings.engine.effectiveMode}`, {
                        defaultValue: settings.engine.effectiveMode,
                      })
                    : none,
                ],
                [
                  t('ux.validation.set.D.inspector'),
                  t('ux.validation.set.D.inspectorValue', { n: settings.engine.inspectorConditions }),
                ],
              ];
  return (
    <>
      <dl className={styles.kv}>
        {rows.map(([name, value]) => (
          <div key={name}>
            <dt>{name}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      <p className={styles.note}>{t('ux.validation.set.note')}</p>
    </>
  );
}
