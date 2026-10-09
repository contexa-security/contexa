import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { benchmarkRunsHref, type BenchmarkPick } from '../../api/benchmark';
import { ActionChip } from '../../components/common/ActionChip';
import { SourceMark } from '../../components/common/SourceMark';
import { useUrlModal } from '../../components/common/useUrlModal';
import { Icon } from '../../components/Icon';
import { NextLink } from '../../components/journey/StepParts';
import { CONTROL_ORDER } from '../../domain/verdict';
import { utcTime } from '../../journey/format';
import experience from '../try/Experience.module.css';
import { BenchScreen } from './BenchScreen';
import { controlName, useBenchView } from './benchData';
import { BENCH_MODALS, fraction, useBenchSetting, useBenchSuite } from './benchPlace';
import styles from './Bench.module.css';

const QUESTIONS = ['mostStopped', 'mostFalseBlock', 'cleanMostStopped'] as const;

/**
 * B1, the summary (bench-1, 7.8): the measurement's range in one line, three questions answered by the approaches the
 * measurement names (ties name all), and one table of every approach's three scores with how to read it next to it.
 * A row opens the approach's card; the case group switch shows the same view over the cases the rule controls were
 * not written for. Every number is the portal's count of the setting's protocol runs.
 */
export default function BenchSummaryPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const { setting, search } = useBenchSetting();
  const { view, empty, state } = useBenchView();
  const { suite, controls, conclusions } = useBenchSuite(view);
  const approach = useUrlModal(BENCH_MODALS.approach, ['control']);
  const method = useUrlModal(BENCH_MODALS.method);
  const spec = view?.spec ?? null;
  const names = (pick: BenchmarkPick) => pick.controls.map((control) => controlName(t, control)).join(' · ');
  const chooseSuite = (next: string | null) => {
    const changed = new URLSearchParams(params);
    if (next) {
      changed.set('suite', next);
    } else {
      changed.delete('suite');
    }
    setParams(changed, { replace: true });
  };
  return (
    <BenchScreen
      view="summary"
      title={t('benchmark.summary.title')}
      purpose={
        view && spec
          ? t('benchmark.summary.scope', {
              from: utcTime(spec.firstRunAt).slice(0, 16),
              to: utcTime(spec.lastRunAt).slice(0, 16),
              cases: view.scope.cases,
              runs: view.scope.runs,
              repeat: view.scope.protocols.map((protocol) => protocol.repeat).join(', ') || '-',
              unresolved: view.unresolvedRuns,
            })
          : t('benchmark.summary.purpose')
      }
      source={
        view && spec ? (
          <SourceMark kind="MEASUREMENT" measured>
            {t('benchmark.summary.source', {
              protocol: view.scope.protocols.map((protocol) => protocol.protocolId).join(', '),
              setting: spec.settingHash.slice(0, 12),
            })}
          </SourceMark>
        ) : null
      }
      more={
        view ? (
          <>
            <ActionChip onClick={() => method.show()} icon="info" variant="open">
              {t('benchmark.method.open')}
            </ActionChip>
            <ActionChip
              download={{ href: benchmarkRunsHref(setting), name: 'contexa-benchmark-runs.json' }}
              icon="download"
              variant="open"
            >
              {t('benchmark.summary.raw')}
            </ActionChip>
          </>
        ) : null
      }
      main={<NextLink to={`/benchmark/cases${search}`} label={t('benchmark.toCases')} />}
    >
      {state}
      {empty ? <p className={experience.lead}>{t('bench.empty')}</p> : null}
      {view && conclusions ? (
        <>
          {view.suites.length > 0 ? (
            <div className={styles.filters} role="group" aria-label={t('benchmark.suite.label')}>
              <button
                type="button"
                className={styles.filter}
                aria-pressed={suite === null}
                onClick={() => chooseSuite(null)}
              >
                {t('benchmark.suite.all')}
              </button>
              {view.suites.map((candidate) => (
                <button
                  key={candidate.suite}
                  type="button"
                  className={styles.filter}
                  aria-pressed={suite?.suite === candidate.suite}
                  onClick={() => chooseSuite(candidate.suite)}
                >
                  {t(`benchmark.suite.${candidate.suite}`, { defaultValue: candidate.suite })}
                </button>
              ))}
            </div>
          ) : null}
          <ul className={styles.questions}>
            {QUESTIONS.map((question) => {
              const pick = conclusions[question];
              return (
                <li key={question} className={styles.question}>
                  <p className={styles.questionText}>{t(`benchmark.question.${question}`)}</p>
                  <p className={styles.questionAnswer}>
                    {pick.controls.length > 0 ? names(pick) : t(`benchmark.answerNone.${question}`)}
                  </p>
                  {pick.controls.length > 0 ? (
                    <p className={styles.questionValue}>
                      {t(`benchmark.answerValue.${question}`, { hits: pick.hits, total: pick.total })}
                    </p>
                  ) : null}
                </li>
              );
            })}
          </ul>
          <div className={styles.tableArea}>
            <table className={styles.table}>
              <caption className={styles.caption}>
                <span>{t('benchmark.table.caption')}</span>
                <span>{t('benchmark.table.captionCells')}</span>
              </caption>
              <thead>
                <tr>
                  <th scope="col">{t('benchmark.column.control')}</th>
                  <th scope="col">{t('benchmark.column.stopped')}</th>
                  <th scope="col">{t('benchmark.column.stoppedAny')}</th>
                  <th scope="col">{t('benchmark.column.notBlocked')}</th>
                </tr>
              </thead>
              <tbody>
                {CONTROL_ORDER.map((control) => {
                  const score = controls.find((candidate) => candidate.control === control);
                  if (!score) {
                    return null;
                  }
                  return (
                    <tr key={control} data-contexa={control === 'D' || undefined}>
                      <th scope="row">
                        <button
                          type="button"
                          className={styles.rowButton}
                          onClick={() => approach.show({ control })}
                        >
                          {controlName(t, control)}
                          <Icon name="chevronRight" className={styles.rowIcon} />
                        </button>
                      </th>
                      <td data-label={t('benchmark.column.stopped')}>
                        <span className={styles.values}>
                          <span className={styles.value}>{fraction(score.stopped)}</span>
                          {score.stopped.preliminary ? (
                            <span className={styles.valueNote}>{t('benchmark.preliminary')}</span>
                          ) : null}
                        </span>
                      </td>
                      <td data-label={t('benchmark.column.stoppedAny')}>
                        <span className={styles.values}>
                          <span className={styles.value}>{fraction(score.stoppedAny)}</span>
                          {score.stoppedAny.preliminary ? (
                            <span className={styles.valueNote}>{t('benchmark.preliminary')}</span>
                          ) : null}
                        </span>
                      </td>
                      <td data-label={t('benchmark.column.notBlocked')}>
                        <span className={styles.values}>
                          <span className={styles.value}>{fraction(score.notBlocked)}</span>
                          {score.friction.hits > 0 ? (
                            <span className={styles.valueNote}>
                              {t('benchmark.withCheck', { n: score.friction.hits })}
                            </span>
                          ) : null}
                          {score.notBlocked.preliminary ? (
                            <span className={styles.valueNote}>{t('benchmark.preliminary')}</span>
                          ) : null}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <details className={experience.more}>
              <summary>{t('benchmark.reading.title')}</summary>
              <ul className={styles.plainList}>
                {(['better', 'preliminary', 'same'] as const).map((item) => (
                  <li key={item}>{t(`benchmark.reading.${item}`)}</li>
                ))}
              </ul>
            </details>
          </div>
          <p className={styles.footnote}>{t('benchmark.footnote')}</p>
          {view.specs.length > 1 ? <SettingChoice /> : null}
        </>
      ) : null}
    </BenchScreen>
  );
}

/** Another measurement setting's scores, when there is more than one (R-13): the latest is the default. */
function SettingChoice() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const { view } = useBenchView();
  if (!view?.spec) {
    return null;
  }
  return (
    <details className={experience.more}>
      <summary>{t('benchmark.setting.open')}</summary>
      <label className={experience.foldText}>
        <span>{t('benchmark.setting.label')}</span>
        <select
          className={styles.select}
          value={view.spec.settingHash}
          onChange={(event) => {
            const changed = new URLSearchParams(params);
            if (event.target.value === view.specs[0]?.settingHash) {
              changed.delete('setting');
            } else {
              changed.set('setting', event.target.value);
            }
            setParams(changed, { replace: true });
          }}
        >
          {view.specs.map((candidate, index) => (
            <option key={candidate.settingHash} value={candidate.settingHash}>
              {t(index === 0 ? 'benchmark.setting.latest' : 'benchmark.setting.option', {
                from: utcTime(candidate.firstRunAt).slice(0, 16),
                runs: candidate.protocolRuns,
              })}
            </option>
          ))}
        </select>
      </label>
    </details>
  );
}
