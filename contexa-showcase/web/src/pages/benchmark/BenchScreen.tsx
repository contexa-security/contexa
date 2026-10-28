import { useId, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import {
  benchmarkRunsHref,
  type BenchmarkCase,
  type BenchmarkRate,
  type BenchmarkView,
  type ControlScore,
} from '../../api/benchmark';
import { useCases } from '../../api/anatomy';
import { useVisitor } from '../../api/queries';
import { usePublicSettings } from '../../api/settings';
import { AppHeader } from '../../components/AppHeader';
import { ActionChip } from '../../components/common/ActionChip';
import { TermScope } from '../../components/common/Glossary';
import { Modal } from '../../components/common/Modal';
import { useUrlModal } from '../../components/common/useUrlModal';
import { useDetail } from '../../components/detail/useDetail';
import { Icon } from '../../components/Icon';
import { ApproachSettings } from '../../components/inside/ApproachSettings';
import { ScreenBody } from '../../components/journey/ScreenBody';
import { NextLink } from '../../components/journey/StepParts';
import { CONTROL_ORDER, VERDICTS, type ControlId, type VerdictPresentation } from '../../domain/verdict';
import { count, dollars, seconds, utcTime } from '../../journey/format';
import experience from '../try/Experience.module.css';
import { caseName, controlName, useBenchView } from './benchData';
import {
  BENCH_MODALS,
  BENCH_ORDER,
  BENCH_PATHS,
  fraction,
  percent,
  percentFixed,
  useBenchSetting,
  useBenchSuite,
  type BenchView,
} from './benchPlace';
import styles from './Bench.module.css';
import { inCurrentWords } from '../../domain/caseWords';
import { sentPerCase } from './benchScope';

/** The screen type each view carries for the automatic check (화면재편-구현계획 5절: the table views skip the number limit). */
export type BenchType = 'T5' | 'T6' | 'table';

interface BenchScreenProps {
  readonly view: BenchView;
  readonly type: BenchType;
  readonly title: ReactNode;
  /** What the visitor does on the view, in one line (R-5). */
  readonly purpose: ReactNode;
  readonly children: ReactNode;
  /** The one "see details" chip under the body (R-2). */
  readonly more?: ReactNode;
  /** The one source line under the body (R-10). */
  readonly sourceLine?: ReactNode;
  /** The last view's way out of the benchmark, in place of the next view. */
  readonly main?: ReactNode;
  /** A view's own window (with its own address), mounted beside the benchmark's windows, outside the body. */
  readonly windows?: ReactNode;
}

/**
 * Every benchmark view in the redesigned frame (화면재편-구현계획 RO-3): the top bar names the space and the view, the
 * inside is the one every screen shares (title zone, body, source line, action bar), and the action bar walks the five
 * views in one order: "back" to the view before, the main button asking the next view's question. The windows a view
 * opens (how the record was made, the scores by method, a situation) have their own addresses and are mounted here.
 */
export function BenchScreen({
  view,
  type,
  title,
  purpose,
  children,
  more = null,
  sourceLine = null,
  main,
  windows = null,
}: BenchScreenProps) {
  useVisitor();
  const { t } = useTranslation();
  const { search } = useBenchSetting();
  const at = BENCH_ORDER.indexOf(view);
  // A view beside the walk (the agent part) has no neighbours: back goes to the summary, and only its own main leads on.
  const beside = at < 0;
  const previous = at > 0 ? BENCH_ORDER[at - 1] : beside ? 'summary' : undefined;
  const next = beside ? undefined : BENCH_ORDER[at + 1];
  const back = previous ? { to: `${BENCH_PATHS[previous]}${search}`, label: t('frame.back') } : null;
  const forward =
    main ??
    (next ? <NextLink to={`${BENCH_PATHS[next]}${search}`} label={t(`bench.r7.next.${next}`)} /> : null);
  return (
    <>
      <AppHeader space={{ name: t('frame.space.benchmark'), step: t(`bench.r7.view.${view}`) }} />
      <main id="main" className={experience.page} data-type={type}>
        <TermScope>
          <ScreenBody
            title={title}
            purpose={purpose}
            more={more}
            sourceLine={sourceLine}
            back={back}
            main={forward}
          >
            {children}
          </ScreenBody>
        </TermScope>
      </main>
      <BenchWindows />
      {windows}
    </>
  );
}

/** The source line of a view (R-10): where the numbers come from, and how the record was made on demand. */
export function BenchSource({ text, onOpen }: { readonly text: string; readonly onOpen?: () => void }) {
  const { t } = useTranslation();
  return (
    <>
      <span>{text}</span>
      {onOpen ? (
        <button type="button" className={styles.sourceOpen} onClick={onOpen}>
          {t('frame.source.open')}
        </button>
      ) : null}
    </>
  );
}

/** The one "see details" chip of a view (R-2), opening one of the benchmark's windows. */
export function BenchDetailChip({
  label,
  onClick,
}: {
  readonly label?: string;
  readonly onClick: () => void;
}) {
  const { t } = useTranslation();
  return (
    <button type="button" className={styles.detail} onClick={onClick}>
      <Icon name="search" className={styles.detailIcon} />
      {label ?? t('frame.detail')}
    </button>
  );
}

function BenchWindows() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const method = useUrlModal(BENCH_MODALS.method);
  const approach = useUrlModal(BENCH_MODALS.approach, ['control']);
  const benchCase = useUrlModal(BENCH_MODALS.benchCase, ['case']);
  const { view } = useBenchView();
  const caseKey = benchCase.params.get('case');
  const row = view && caseKey ? (view.cases.find((candidate) => candidate.key === caseKey) ?? null) : null;
  return (
    <>
      <Modal open={method.open} onClose={method.hide} title={t('bench.r7.method.title')} wide>
        {view ? <MethodWindow view={view} /> : null}
      </Modal>
      <Modal open={approach.open} onClose={approach.hide} title={t('bench.r7.scores.title')} wide>
        {view ? <ScoresWindow view={view} /> : null}
      </Modal>
      <Modal
        open={benchCase.open}
        onClose={benchCase.hide}
        title={
          row
            ? t('bench.r7.case.windowTitle', { name: caseName(t, row, language) })
            : t('bench.r7.case.windowLoading')
        }
        wide
      >
        {view && caseKey ? <CaseWindow view={view} caseKey={caseKey} /> : null}
      </Modal>
    </>
  );
}

interface BenchChoiceProps {
  readonly label: string;
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly children: ReactNode;
}

/** A labelled choice (the situations to look at, another setting, method or situation): the label over its select. */
export function BenchChoice({ label, value, onChange, children }: BenchChoiceProps) {
  const id = useId();
  return (
    <div className={styles.choice} data-block>
      <label htmlFor={id} className={styles.choiceLabel}>
        {label}
      </label>
      <select
        id={id}
        className={styles.select}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        {children}
      </select>
    </div>
  );
}

/** A rate's range of variation (95% interval, both ends with one decimal, L-39) and the "few runs yet" mark. */
export function RateRange({
  rate,
  label = true,
}: {
  readonly rate: BenchmarkRate;
  readonly label?: boolean;
}) {
  const { t } = useTranslation();
  const low = percentFixed(rate.low);
  const high = percentFixed(rate.high);
  return (
    <>
      {label ? t('bench.r7.range', { low, high }) : t('bench.r7.rangeValue', { low, high })}
      {rate.preliminary ? ` · ${t('bench.r7.preliminary')}` : ''}
    </>
  );
}

/**
 * How the record was made: the range of what was sent, the formulas, the expected results and the range of
 * variation, the environment, another setting's record, what one judgment costs, what visitors did apart from the
 * scores, the fairness notices and the whole record to download. Moved here from the views so each view keeps one role.
 */
function MethodWindow({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const { setting } = useBenchSetting();
  const spec = view.spec;
  const engine = view.engine;
  const observations = view.observations;
  return (
    <div className={styles.window}>
      {spec ? (
        <p className={styles.windowText}>
          {t('bench.r7.method.scope', {
            from: utcTime(spec.firstRunAt).slice(0, 16),
            to: utcTime(spec.lastRunAt).slice(0, 16),
            cases: view.scope.cases,
            runs: view.scope.runs,
            repeat: sentPerCase(view),
            unresolved: view.unresolvedRuns,
          })}
        </p>
      ) : null}
      <section className={styles.windowPart} aria-labelledby="method-formula">
        <h3 id="method-formula" className={styles.windowTitle}>
          {t('bench.r7.method.formula')}
        </h3>
        <ul className={styles.plainList}>
          {(['stopped', 'stoppedAny', 'notBlocked', 'partial', 'unresolved'] as const).map((item) => (
            <li key={item}>{t(`bench.r7.method.formula.${item}`)}</li>
          ))}
        </ul>
      </section>
      <section className={styles.windowPart} aria-labelledby="method-truth">
        <h3 id="method-truth" className={styles.windowTitle}>
          {t('bench.r7.method.truth')}
        </h3>
        <p className={styles.windowText}>{t('bench.r7.method.truthText')}</p>
        <p className={styles.windowText}>{t('bench.r7.method.interval')}</p>
      </section>
      {spec ? (
        <section className={styles.windowPart} aria-labelledby="method-environment">
          <h3 id="method-environment" className={styles.windowTitle}>
            {t('bench.r7.method.environment')}
          </h3>
          <dl className={styles.facts}>
            <div>
              <dt>{t('bench.r7.method.period')}</dt>
              <dd>
                {t('benchmark.method.periodValue', {
                  from: utcTime(spec.firstRunAt).slice(0, 16),
                  to: utcTime(spec.lastRunAt).slice(0, 16),
                })}
              </dd>
            </div>
            <div>
              <dt>{t('bench.r7.method.model')}</dt>
              <dd>
                <code data-original>{spec.chatModel}</code>
              </dd>
            </div>
            <div>
              <dt>{t('bench.r7.method.setting')}</dt>
              <dd>
                <code data-original>{spec.settingHash.slice(0, 12)}</code>
              </dd>
            </div>
            <div>
              <dt>{t('bench.r7.method.rules')}</dt>
              <dd>
                <code data-original>{spec.ruleVersion.slice(0, 12)}</code>
              </dd>
            </div>
            <div>
              <dt>{t('bench.r7.method.code')}</dt>
              <dd>
                <code data-original>
                  {spec.codeCommit} · {spec.engineVersion}
                </code>
              </dd>
            </div>
            <div>
              <dt>{t('bench.r7.method.protocol')}</dt>
              <dd>
                {view.scope.protocols.map((protocol) => (
                  <code key={protocol.protocolId} data-original>
                    {protocol.protocolId}
                  </code>
                ))}
              </dd>
            </div>
          </dl>
          {view.specs.length > 1 ? <SettingChoice view={view} /> : null}
        </section>
      ) : null}
      <section className={styles.windowPart} aria-labelledby="method-ops">
        <h3 id="method-ops" className={styles.windowTitle}>
          {t('bench.r7.ops.title')}
        </h3>
        {engine ? (
          <>
            <dl className={styles.facts}>
              <div>
                <dt>{t('bench.r7.ops.time')}</dt>
                <dd>
                  {engine.analysisP50Ms === null
                    ? '-'
                    : t('detail.seconds', { s: seconds(engine.analysisP50Ms) })}
                </dd>
              </div>
              <div>
                <dt>{t('bench.r7.ops.cost')}</dt>
                <dd>{engine.costPerDecisionUsd === null ? '-' : `$${dollars(engine.costPerDecisionUsd)}`}</dd>
              </div>
              <div>
                <dt>{t('bench.r7.ops.decisions')}</dt>
                <dd>{count(engine.decisions, language)}</dd>
              </div>
            </dl>
            <p className={styles.windowText}>
              {t('bench.r7.ops.detail', {
                p95: engine.analysisP95Ms === null ? '-' : seconds(engine.analysisP95Ms),
                tokens:
                  engine.tokensPerDecision === null
                    ? '-'
                    : count(Math.round(engine.tokensPerDecision), language),
                calls: engine.modelCallsPerDecision === null ? '-' : engine.modelCallsPerDecision.toFixed(1),
              })}
            </p>
            {engine.priceSource ? (
              <p className={styles.note}>
                {t('bench.r7.ops.price')} <code data-original>{engine.priceSource}</code>
              </p>
            ) : null}
          </>
        ) : (
          <p className={styles.windowText}>{t('bench.r7.ops.none')}</p>
        )}
      </section>
      <section className={styles.windowPart} aria-labelledby="method-visitors">
        <h3 id="method-visitors" className={styles.windowTitle}>
          {t('bench.r7.visitors.title')}
        </h3>
        <ul className={styles.plainList}>
          <li>
            {t('bench.r7.visitors.runs', {
              live: count(observations.liveRuns, language),
              lab: count(observations.labRuns, language),
            })}
          </li>
          <li>
            {t('bench.r7.visitors.predictions', {
              hits: observations.predictions.hits,
              total: observations.predictions.total,
              rate: percent(observations.predictions.rate),
            })}
          </li>
          <li>
            {t('bench.r7.visitors.assessments', {
              n: count(observations.assessments, language),
              people: count(observations.assessors, language),
            })}
          </li>
        </ul>
        <p className={styles.note}>{t('bench.r7.visitors.apart')}</p>
      </section>
      <details className={experience.more}>
        <summary>{t('bench.r7.method.notices')}</summary>
        <ul className={styles.plainList}>
          {view.notices.map((notice) => (
            <li key={notice}>{t(`bench.r7.notice.${notice}`, { defaultValue: notice })}</li>
          ))}
        </ul>
      </details>
      <div className={styles.windowActions}>
        <ActionChip
          download={{ href: benchmarkRunsHref(setting), name: 'contexa-benchmark-runs.json' }}
          icon="download"
          variant="open"
        >
          {t('bench.r7.raw')}
        </ActionChip>
      </div>
    </div>
  );
}

/** Another setting's record, when there is more than one (R-13): the latest is the default. */
function SettingChoice({ view }: { readonly view: BenchmarkView }) {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  return (
    <BenchChoice
      label={t('bench.r7.method.settingLabel')}
      value={view.spec?.settingHash ?? ''}
      onChange={(value) => {
        // The latest setting is the default: it leaves the address without a setting.
        const changed = new URLSearchParams(params);
        if (value === view.specs[0]?.settingHash) {
          changed.delete('setting');
        } else {
          changed.set('setting', value);
        }
        setParams(changed, { replace: true });
      }}
    >
      {view.specs.map((candidate, index) => (
        <option key={candidate.settingHash} value={candidate.settingHash}>
          {t(index === 0 ? 'bench.r7.method.settingLatest' : 'bench.r7.method.settingOption', {
            from: utcTime(candidate.firstRunAt).slice(0, 16),
            runs: candidate.protocolRuns,
          })}
        </option>
      ))}
    </BenchChoice>
  );
}

const SCORES = ['stopped', 'stoppedAny', 'notBlocked'] as const;

/** A score's cell: the server's count as "hits/total", with "few runs yet" and the identity checks under it. */
function ScoreCell({
  score,
  name,
}: {
  readonly score: ControlScore;
  readonly name: (typeof SCORES)[number];
}) {
  const { t } = useTranslation();
  const rate = score[name];
  return (
    <span className={styles.values}>
      <span className={styles.value}>{fraction(rate)}</span>
      {name === 'notBlocked' && score.friction.hits > 0 ? (
        <span className={styles.valueNote}>{t('benchmark.withCheck', { n: score.friction.hits })}</span>
      ) : null}
      {rate.preliminary ? <span className={styles.valueNote}>{t('bench.r7.preliminary')}</span> : null}
    </span>
  );
}

/**
 * The scores by method (the summary's "see details"): every method's three scores in one table as the server counted
 * them, how to read them, then one method in detail (its ranges of variation, what it handled wrong by kind, its
 * settings in this demo), the method chosen in the window's own address (?control=).
 */
function ScoresWindow({ view }: { readonly view: BenchmarkView }) {
  const { t } = useTranslation();
  const settings = usePublicSettings();
  const approach = useUrlModal(BENCH_MODALS.approach, ['control']);
  const { suite, controls } = useBenchSuite(view);
  const asked = approach.params.get('control');
  const shown =
    controls.find((score) => score.control === asked) ?? controls.find((s) => s.control === 'D') ?? null;
  return (
    <div className={styles.window}>
      {suite ? (
        <p className={styles.windowText}>
          {t('bench.r7.scores.suiteLine', {
            name: t(`bench.r7.suite.${suite.suite}`, { defaultValue: suite.suite }),
          })}
        </p>
      ) : null}
      <div className={styles.tableScroll} role="region" aria-label={t('bench.r7.scores.title')} tabIndex={0}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th scope="col">{t('bench.r7.scores.control')}</th>
              {SCORES.map((name) => (
                <th key={name} scope="col">
                  {t(`bench.r7.score.${name}`)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {CONTROL_ORDER.map((control) => {
              const score = controls.find((candidate) => candidate.control === control);
              return score ? (
                <tr key={control} data-contexa={control === 'D' || undefined}>
                  <th scope="row">{controlName(t, control)}</th>
                  {SCORES.map((name) => (
                    <td key={name}>
                      <ScoreCell score={score} name={name} />
                    </td>
                  ))}
                </tr>
              ) : null;
            })}
          </tbody>
        </table>
      </div>
      <p className={styles.note}>{t('bench.r7.footnote')}</p>
      <section className={styles.windowPart} aria-labelledby="scores-reading">
        <h3 id="scores-reading" className={styles.windowTitle}>
          {t('bench.r7.scores.reading')}
        </h3>
        <ul className={styles.plainList}>
          {(['better', 'preliminary', 'same'] as const).map((item) => (
            <li key={item}>{t(`bench.r7.scores.reading.${item}`)}</li>
          ))}
        </ul>
      </section>
      {shown ? (
        <section className={styles.windowPart}>
          <BenchChoice
            label={t('bench.r7.scores.choose')}
            value={shown.control}
            onChange={(control) => approach.change({ control })}
          >
            {CONTROL_ORDER.filter((control) => controls.some((score) => score.control === control)).map(
              (control) => (
                <option key={control} value={control}>
                  {t(`control.${control}.name`)}
                </option>
              ),
            )}
          </BenchChoice>
          <dl className={styles.scoreCards}>
            {SCORES.map((name) => (
              <div key={name}>
                <dt>{t(`bench.r7.score.${name}`)}</dt>
                <dd className={styles.scoreValue}>{fraction(shown[name])}</dd>
                <dd className={styles.scoreNote}>
                  <RateRange rate={shown[name]} />
                </dd>
              </div>
            ))}
          </dl>
          <h4 className={styles.windowTitle}>{t('bench.r7.scores.wrong')}</h4>
          <ul className={styles.plainList}>
            <li>{t('bench.r7.scores.missed', { n: shown.missed })}</li>
            <li>{t('bench.r7.scores.partly', { n: shown.partlyStopped })}</li>
            <li>{t('bench.r7.scores.falseBlock', { n: shown.falseBlock.hits })}</li>
            <li>
              {t('bench.r7.scores.unresolved', {
                attack: shown.attackUnresolved,
                normal: shown.normalUnresolved,
              })}
            </li>
          </ul>
          <h4 className={styles.windowTitle}>{t('benchmark.approach.settings')}</h4>
          {settings.data ? (
            <ApproachSettings control={shown.control} settings={settings.data} />
          ) : settings.isError ? (
            <p className={styles.windowText}>{t('settings.unavailable')}</p>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}

/** An engine action in the visitors' word for it, the action itself where it is none of the four. */
function actionWord(t: ReturnType<typeof useTranslation>['t'], action: string): string {
  const found = (VERDICTS as Readonly<Record<string, VerdictPresentation | undefined>>)[action];
  return found ? t(found.labelKey) : action;
}

const GROUPS = ['THREAT', 'NORMAL', 'UNCERTAIN'] as const;

/** What handling the situation right means: stop it, let it pass, or nothing set in advance. */
function answerOf(row: BenchmarkCase): 'stop' | 'pass' | 'none' {
  return row.classification === 'THREAT' ? 'stop' : row.classification === 'NORMAL' ? 'pass' : 'none';
}

/**
 * A situation: another one to choose in place, what handling it right means and why, the handlings that count as
 * right (neutral chips, B-20 of docs/showcase/영상전-검토.md, and why holding counts), every method's times handled
 * right over times counted, and the runs sent in it, each opening the decision details in this window's place (the
 * browser's back button returns here).
 */
function CaseWindow({ view, caseKey }: { readonly view: BenchmarkView; readonly caseKey: string }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const detail = useDetail();
  const benchCase = useUrlModal(BENCH_MODALS.benchCase, ['case']);
  const catalog = useCases().data ?? null;
  const row = view.cases.find((candidate) => candidate.key === caseKey) ?? null;
  const definition = catalog?.cases.find((candidate) => candidate.key === caseKey) ?? null;
  const choice = (
    <BenchChoice
      label={t('bench.r7.case.choose')}
      value={row ? caseKey : ''}
      onChange={(key) => benchCase.change({ case: key })}
    >
      {row ? null : <option value="" />}
      {GROUPS.map((group) => {
        const rows = view.cases.filter((candidate) => candidate.classification === group);
        return rows.length > 0 ? (
          <optgroup key={group} label={t(`bench.r7.cases.groupName.${group}`)}>
            {rows.map((candidate) => (
              <option key={candidate.key} value={candidate.key}>
                {caseName(t, candidate, language)}
              </option>
            ))}
          </optgroup>
        ) : null;
      })}
    </BenchChoice>
  );
  if (!row) {
    return (
      <div className={styles.window}>
        {choice}
        <p className={styles.windowText}>{t('bench.r7.case.notFound')}</p>
      </div>
    );
  }
  const answer = answerOf(row);
  return (
    <div className={styles.window}>
      {choice}
      <p className={styles.answerLine}>
        <span className={styles.answer} data-answer={answer}>
          {t(`bench.r7.case.answer.${answer}`)}
        </span>
        {definition && definition.allowedActions.length > 0 ? (
          <span className={styles.chips}>
            <span className={styles.label}>{t('bench.r7.case.allowed')}</span>
            {definition.allowedActions.map((action) => (
              <span key={action} className={styles.allowedChip} data-allowed={action}>
                {actionWord(t, action)}
              </span>
            ))}
          </span>
        ) : null}
      </p>
      {definition?.allowedActions.includes('ESCALATE') ? (
        <p className={styles.note}>{t('bench.r7.case.held')}</p>
      ) : null}
      {definition?.rationale[language] ? (
        <p className={styles.windowText}>{inCurrentWords(definition.rationale[language], language)}</p>
      ) : null}
      {definition?.counterpoint[language] ? (
        <details className={experience.more}>
          <summary>{t('bench.r7.case.counterpoint')}</summary>
          <p className={experience.foldText}>{inCurrentWords(definition.counterpoint[language], language)}</p>
        </details>
      ) : null}
      {/* B-20: each cell named by the score it counts (the server's rule: an attack stopped at some request, normal
          work passed with or without an extra check), as the scores by method name them. */}
      <dl className={styles.caseCells}>
        {CONTROL_ORDER.map((control: ControlId) => {
          const cell = row.cells[control];
          return (
            <div key={control} data-state={cell?.state ?? 'NONE'}>
              <dt>{controlName(t, control)}</dt>
              <dd>
                {cell
                  ? t('bench.r7.case.cell', {
                      score: t(answer === 'stop' ? 'bench.r7.score.stoppedAny' : 'bench.r7.score.notBlocked'),
                      right: cell.right,
                      counted: cell.counted,
                    })
                  : t('bench.r7.notCounted')}
              </dd>
            </div>
          );
        })}
      </dl>
      <section className={styles.windowPart} aria-labelledby="case-runs">
        <h3 id="case-runs" className={styles.windowTitle}>
          {t('bench.r7.case.runs', { n: count(row.runs, language) })}
        </h3>
        <ul className={styles.runChips}>
          {row.runIds.map((runId, index) => (
            <li key={runId} className={styles.runChip}>
              <ActionChip onClick={() => detail.show(runId)} icon="search" variant="open" size="sm">
                {t('bench.r7.case.openRun', { n: index + 1 })}
              </ActionChip>
              <code data-original className={styles.runId}>
                {runId}
              </code>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
