import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { BenchmarkView, ControlScore } from '../../api/benchmark';
import { useCases } from '../../api/anatomy';
import { useVisitor } from '../../api/queries';
import { usePublicSettings } from '../../api/settings';
import { AppHeader } from '../../components/AppHeader';
import { ActionChip } from '../../components/common/ActionChip';
import { TermScope } from '../../components/common/Glossary';
import { Modal } from '../../components/common/Modal';
import { useUrlModal } from '../../components/common/useUrlModal';
import { useDetail } from '../../components/detail/useDetail';
import { ApproachSettings } from '../../components/inside/ApproachSettings';
import { BenchBar, type BenchView } from '../../components/journey/JourneyParts';
import { ActionBar, MoreRow, StepHeader } from '../../components/journey/StepParts';
import { VerdictChip } from '../../components/VerdictChip';
import { CONTROL_ORDER, VERDICTS, type ControlId, type Verdict } from '../../domain/verdict';
import { count, utcTime } from '../../journey/format';
import experience from '../try/Experience.module.css';
import { controlName, useBenchView } from './benchData';
import { BENCH_MODALS, fraction, percent, useBenchSetting, useBenchSuite } from './benchPlace';
import styles from './Bench.module.css';

interface BenchScreenProps {
  readonly view: BenchView;
  readonly title: ReactNode;
  readonly purpose: ReactNode;
  readonly source?: ReactNode;
  readonly children: ReactNode;
  /** The chips that open more of the content (windows, the raw data), right under it. */
  readonly more?: ReactNode;
  readonly back?: { readonly to: string; readonly label: string } | null;
  readonly main?: ReactNode;
}

/**
 * Every benchmark view in the routes' one order and set of places (U-9): the benchmark's place band with its four
 * views, the head, the content, the "more" row and the action area. The windows a view opens (how it was measured, an
 * approach's card, a case) have their own addresses and are mounted here, so each view can open them.
 */
export function BenchScreen({
  view,
  title,
  purpose,
  source = null,
  children,
  more = null,
  back = null,
  main = null,
}: BenchScreenProps) {
  useVisitor();
  const { search } = useBenchSetting();
  return (
    <>
      <AppHeader />
      <main id="main" className={experience.page}>
        <BenchBar view={view} search={search} />
        <TermScope>
          <div className={experience.step}>
            <StepHeader title={title} purpose={purpose} source={source} />
            {children}
            {more ? <MoreRow>{more}</MoreRow> : null}
            <ActionBar back={back} main={main} skip={false} />
          </div>
        </TermScope>
      </main>
      <BenchWindows />
    </>
  );
}

function BenchWindows() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const method = useUrlModal(BENCH_MODALS.method);
  const approach = useUrlModal(BENCH_MODALS.approach, ['control']);
  const benchCase = useUrlModal(BENCH_MODALS.benchCase, ['case']);
  const { view } = useBenchView();
  const { controls } = useBenchSuite(view);
  const control = controls.find((score) => score.control === approach.params.get('control')) ?? null;
  const caseKey = benchCase.params.get('case');
  return (
    <>
      <Modal open={method.open} onClose={method.hide} title={t('benchmark.method.title')} wide>
        {view ? <MethodWindow view={view} /> : null}
      </Modal>
      <Modal
        open={approach.open}
        onClose={approach.hide}
        title={control ? t('benchmark.approach.title', { name: controlName(t, control.control) }) : ''}
        wide
      >
        {control ? <ApproachWindow score={control} /> : null}
      </Modal>
      <Modal
        open={benchCase.open}
        onClose={benchCase.hide}
        title={
          view && caseKey
            ? t('benchmark.case.title', { name: caseTitle(view, caseKey, language) })
            : t('benchmark.case.titleLoading')
        }
        wide
      >
        {view && caseKey ? <CaseWindow view={view} caseKey={caseKey} /> : null}
      </Modal>
    </>
  );
}

function caseTitle(view: BenchmarkView, key: string, language: string): string {
  return view.cases.find((candidate) => candidate.key === key)?.title[language] ?? key;
}

/** How it was measured (bench-3): the formulas, the ground truth, what the interval means, the environment. */
function MethodWindow({ view }: { readonly view: BenchmarkView }) {
  const { t } = useTranslation();
  const spec = view.spec;
  return (
    <div className={styles.window}>
      <section className={styles.windowPart} aria-labelledby="method-formula">
        <h3 id="method-formula" className={experience.panelTitle}>
          {t('benchmark.method.formula')}
        </h3>
        <ul className={styles.plainList}>
          {(['stopped', 'stoppedAny', 'notBlocked', 'partial', 'unresolved'] as const).map((item) => (
            <li key={item}>{t(`benchmark.method.formula.${item}`)}</li>
          ))}
        </ul>
      </section>
      <section className={styles.windowPart} aria-labelledby="method-truth">
        <h3 id="method-truth" className={experience.panelTitle}>
          {t('benchmark.method.truth')}
        </h3>
        <p className={experience.lead}>{t('benchmark.method.truthText')}</p>
        <p className={experience.lead}>{t('benchmark.method.interval')}</p>
      </section>
      {spec ? (
        <section className={styles.windowPart} aria-labelledby="method-environment">
          <h3 id="method-environment" className={experience.panelTitle}>
            {t('benchmark.method.environment')}
          </h3>
          <dl className={styles.facts}>
            <div>
              <dt>{t('benchmark.method.period')}</dt>
              <dd>
                {t('benchmark.method.periodValue', {
                  from: utcTime(spec.firstRunAt).slice(0, 16),
                  to: utcTime(spec.lastRunAt).slice(0, 16),
                })}
              </dd>
            </div>
            <div>
              <dt>{t('benchmark.method.model')}</dt>
              <dd>
                <code data-original>{spec.chatModel}</code>
              </dd>
            </div>
            <div>
              <dt>{t('benchmark.method.setting')}</dt>
              <dd>
                <code data-original>{spec.settingHash.slice(0, 12)}</code>
              </dd>
            </div>
            <div>
              <dt>{t('benchmark.method.code')}</dt>
              <dd>
                <code data-original>
                  {spec.codeCommit} · {spec.engineVersion}
                </code>
              </dd>
            </div>
            <div>
              <dt>{t('benchmark.method.protocol')}</dt>
              <dd>
                {view.scope.protocols.map((protocol) => (
                  <code key={protocol.protocolId} data-original>
                    {protocol.protocolId}
                  </code>
                ))}
              </dd>
            </div>
          </dl>
        </section>
      ) : null}
      <details className={experience.more}>
        <summary>{t('benchmark.method.notices')}</summary>
        <ul className={styles.plainList}>
          {view.notices.map((notice) => (
            <li key={notice}>{t(`bench.notice.${notice}`)}</li>
          ))}
        </ul>
      </details>
    </div>
  );
}

/** One approach's card (bench-3): its three scores with their intervals, its wrong answers by kind, its settings. */
function ApproachWindow({ score }: { readonly score: ControlScore }) {
  const { t } = useTranslation();
  const settings = usePublicSettings();
  const rates = [
    ['stopped', score.stopped],
    ['stoppedAny', score.stoppedAny],
    ['notBlocked', score.notBlocked],
  ] as const;
  return (
    <div className={styles.window}>
      <dl className={styles.scoreCards}>
        {rates.map(([name, rate]) => (
          <div key={name}>
            <dt>{t(`benchmark.column.${name}`)}</dt>
            <dd className={styles.scoreValue}>{fraction(rate)}</dd>
            <dd className={styles.scoreNote}>
              {t('benchmark.interval', { low: percent(rate.low), high: percent(rate.high) })}
              {rate.preliminary ? ` · ${t('benchmark.preliminary')}` : ''}
            </dd>
          </div>
        ))}
      </dl>
      <section className={styles.windowPart} aria-labelledby="approach-wrong">
        <h3 id="approach-wrong" className={experience.panelTitle}>
          {t('benchmark.approach.wrong')}
        </h3>
        <ul className={styles.plainList}>
          <li>{t('benchmark.approach.missed', { n: score.missed })}</li>
          <li>{t('benchmark.approach.partly', { n: score.partlyStopped })}</li>
          <li>{t('benchmark.approach.falseBlock', { n: score.falseBlock.hits })}</li>
          <li>
            {t('benchmark.approach.unresolved', {
              attack: score.attackUnresolved,
              normal: score.normalUnresolved,
            })}
          </li>
        </ul>
      </section>
      <section className={styles.windowPart} aria-labelledby="approach-settings">
        <h3 id="approach-settings" className={experience.panelTitle}>
          {t('benchmark.approach.settings')}
        </h3>
        {settings.data ? (
          <ApproachSettings control={score.control} settings={settings.data} />
        ) : settings.isError ? (
          <p className={experience.lead}>{t('settings.unavailable')}</p>
        ) : null}
      </section>
    </div>
  );
}

function verdictOf(action: string): Verdict {
  return action in VERDICTS ? (action as Verdict) : 'NONE';
}

/**
 * A case (bench-3): its right answer and why, the responses that count as right, every approach's runs handled right
 * over scored runs, and its measured runs, each opening the decision details in this window's place (the browser's
 * back button returns here).
 */
function CaseWindow({ view, caseKey }: { readonly view: BenchmarkView; readonly caseKey: string }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const detail = useDetail();
  const catalog = useCases().data ?? null;
  const row = view.cases.find((candidate) => candidate.key === caseKey) ?? null;
  const definition = catalog?.cases.find((candidate) => candidate.key === caseKey) ?? null;
  if (!row) {
    return <p className={experience.lead}>{t('benchmark.case.notFound')}</p>;
  }
  const answer = row.classification === 'THREAT' ? 'stop' : row.classification === 'NORMAL' ? 'pass' : 'none';
  return (
    <div className={styles.window}>
      <p className={styles.answerLine}>
        <span className={styles.answer} data-answer={answer}>
          {t(`labCase.answer.${answer}`)}
        </span>
        {definition && definition.allowedActions.length > 0 ? (
          <span className={styles.chips}>
            <span className={styles.label}>{t('detail.answer.allowed')}</span>
            {definition.allowedActions.map((action) => (
              <VerdictChip key={action} verdict={verdictOf(action)} />
            ))}
          </span>
        ) : null}
      </p>
      {definition?.rationale[language] ? (
        <p className={experience.lead}>{definition.rationale[language]}</p>
      ) : null}
      {definition?.counterpoint[language] ? (
        <details className={experience.more}>
          <summary>{t('detail.answer.counterpoint')}</summary>
          <p className={experience.foldText}>{definition.counterpoint[language]}</p>
        </details>
      ) : null}
      <dl className={styles.caseCells}>
        {CONTROL_ORDER.map((control: ControlId) => {
          const cell = row.cells[control];
          return (
            <div key={control} data-state={cell?.state ?? 'NONE'}>
              <dt>{controlName(t, control)}</dt>
              <dd>{cell ? `${cell.right}/${cell.counted}` : t('benchmark.notScored')}</dd>
            </div>
          );
        })}
      </dl>
      <section className={styles.windowPart} aria-labelledby="case-runs">
        <h3 id="case-runs" className={experience.panelTitle}>
          {t('benchmark.case.runs', { n: count(row.runs, language) })}
        </h3>
        <ul className={styles.runChips}>
          {row.runIds.map((runId) => (
            <li key={runId}>
              <ActionChip onClick={() => detail.show(runId)} icon="search" variant="open" size="sm">
                <code data-original>{runId}</code>
              </ActionChip>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
