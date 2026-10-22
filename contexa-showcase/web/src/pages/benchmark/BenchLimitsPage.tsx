import { useTranslation } from 'react-i18next';
import { useUrlModal } from '../../components/common/useUrlModal';
import { NextLink } from '../../components/journey/StepParts';
import { count } from '../../journey/format';
import { BenchDetailChip, BenchScreen, BenchSource } from './BenchScreen';
import { caseName, useBenchView } from './benchData';
import { BENCH_MODALS, fraction } from './benchPlace';
import { judgmentOthers } from './benchShapes';
import { WrongCases } from './charts/WrongCases';
import styles from './Bench.module.css';

/**
 * The limits (화면재편-구현계획 RO-3; B-6 of docs/showcase/벤치마크-구현계획.md): the result in one line (the attacks
 * Contexa let through every time they were sent, or none), the attacks it let through and the normal work it blocked at
 * least once as the server flagged them, each with a cell per run and the reason the model wrote, Contexa's three
 * numbers (stopped with nothing out, stopped in the end, items leaked in attacks) with the refusals of the sign-in check
 * they hold, why the first is low from the judgment and timing count (its "other" runs named with their results), and
 * the two limits of the explanations. "See details" opens the first missed situation's window; the main button leads
 * out of the benchmark to the lab, to change a condition and send it.
 */
export default function BenchLimitsPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const method = useUrlModal(BENCH_MODALS.method);
  const benchCase = useUrlModal(BENCH_MODALS.benchCase, ['case']);
  const { view, empty, state } = useBenchView();
  const contexa = view?.controls.find((score) => score.control === 'D') ?? null;
  const others = view ? judgmentOthers(view) : [];
  const nameOf = (key: string) => {
    const row = view?.cases.find((candidate) => candidate.key === key);
    return row ? caseName(t, row, language) : key;
  };
  const missed = (view?.missedEveryRunCases ?? [])
    .map((key) => view?.cases.find((row) => row.key === key))
    .filter((row) => row !== undefined);
  const first = missed[0] ?? null;
  return (
    <BenchScreen
      view="limits"
      type="T6"
      title={t('bench.r7.limits.title')}
      purpose={t('bench.r7.limits.guide')}
      more={first ? <BenchDetailChip onClick={() => benchCase.show({ case: first.key })} /> : null}
      sourceLine={
        view && contexa ? (
          <BenchSource text={t('frame.source.measured')} onOpen={() => method.show()} />
        ) : null
      }
      main={<NextLink to="/lab" label={t('bench.r7.next.lab')} />}
    >
      {state}
      {empty ? <p className={styles.line}>{t('bench.r7.empty')}</p> : null}
      {view && contexa ? (
        <>
          <p className={styles.result}>
            {missed.length > 0
              ? t('bench.r7.limits.missed', { count: missed.length })
              : t('bench.r7.limits.missedNone')}
          </p>
          <WrongCases
            rows={view.cases.filter((row) => row.classification === 'THREAT' && row.contexaWrong)}
            wrongRuns={view.wrongRuns}
            nameOf={(row) => caseName(t, row, language)}
            title={t('bench.chart.limits.missedTitle')}
            none={t('bench.chart.limits.none.THREAT')}
          />
          <WrongCases
            rows={view.cases.filter((row) => row.classification === 'NORMAL' && row.contexaWrong)}
            wrongRuns={view.wrongRuns}
            nameOf={(row) => caseName(t, row, language)}
            title={t('bench.chart.limits.haltedTitle')}
            none={t('bench.chart.limits.none.NORMAL')}
          />
          <dl className={styles.figures}>
            <div>
              <dt>{t('bench.r7.score.stopped')}</dt>
              <dd>{fraction(contexa.stopped)}</dd>
            </div>
            <div>
              <dt>{t('bench.r7.score.stoppedAny')}</dt>
              <dd>{fraction(contexa.stoppedAny)}</dd>
            </div>
            <div>
              <dt>{t('bench.r7.limits.exposed')}</dt>
              <dd>{t('bench.r7.items', { items: count(contexa.exposedItems, language) })}</dd>
            </div>
          </dl>
          {view.judgmentTiming.STATIC_REFUSAL > 0 ? (
            <p className={styles.note}>
              {t('bench.r7.limits.staticNote', { count: view.judgmentTiming.STATIC_REFUSAL })}
            </p>
          ) : null}
          <div className={styles.callout}>
            <p className={styles.calloutLine}>
              {t('bench.r7.limits.why', {
                timing: view.judgmentTiming.NEXT_REQUEST,
                judged: view.judgmentTiming.JUDGED_ALLOW,
              })}
            </p>
            {others.length > 0 ? (
              <p className={styles.calloutLine}>
                {t('bench.r7.limits.whyOthers', {
                  n: view.judgmentTiming.OTHER,
                  runs: others
                    .map((run) =>
                      t('bench.r7.limits.whyOther', {
                        name: nameOf(run.caseKey),
                        result: t(`main.result.${run.result}`, { defaultValue: run.result }),
                      }),
                    )
                    .join(' · '),
                })}
              </p>
            ) : null}
          </div>
          <section className={styles.explain} aria-labelledby="limits-explain">
            <h2 id="limits-explain" className={styles.explainTitle}>
              {t('bench.r7.limits.explainTitle')}
            </h2>
            <ul className={styles.plainList}>
              {/* The explanations' limits of the bundle the setting ran: the v20 ones do not hold for v21. */}
              {(view.spec?.promptBundles ?? []).some((bundle) => bundle.includes('-v21')) ? (
                <>
                  <li>{t('bench.chart.limits.explain.retry')}</li>
                  <li>{t('bench.chart.limits.explain.async')}</li>
                </>
              ) : (
                <>
                  <li>{t('bench.r7.limits.explain.approval')}</li>
                  <li>{t('bench.r7.limits.explain.inspector')}</li>
                </>
              )}
            </ul>
          </section>
        </>
      ) : null}
    </BenchScreen>
  );
}
