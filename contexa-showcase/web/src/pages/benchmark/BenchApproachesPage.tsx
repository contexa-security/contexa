import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import type { BenchmarkPick, ControlScore } from '../../api/benchmark';
import { useUrlModal } from '../../components/common/useUrlModal';
import { CONTROL_ORDER } from '../../domain/verdict';
import { BenchChoice, BenchDetailChip, BenchScreen, BenchSource } from './BenchScreen';
import { controlName, useBenchView } from './benchData';
import { BENCH_MODALS, useBenchSuite } from './benchPlace';
import { RateScatter } from './charts/RateScatter';
import styles from './Bench.module.css';

const QUESTIONS = ['mostStopped', 'mostFalseBlock', 'cleanMostStopped'] as const;

/**
 * B-2 of docs/showcase/벤치마크-구현계획.md: the five approaches on one chart, attacks stopped (at any step) up and normal
 * work blocked to the right, each with its 95% interval, for every case or a named group, with how many of Contexa's
 * stops the sign-in check made first; then the three questions the server answers (a tie names all). Every rate,
 * interval and pick is the portal's.
 */
export default function BenchApproachesPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const { view, empty, state } = useBenchView();
  const { suite, controls, conclusions } = useBenchSuite(view);
  const scores = useUrlModal(BENCH_MODALS.approach, ['control']);
  const method = useUrlModal(BENCH_MODALS.method);
  const names = (pick: BenchmarkPick) => pick.controls.map((control) => controlName(t, control)).join(' · ');
  const chooseSuite = (next: string) => {
    const changed = new URLSearchParams(params);
    if (next) {
      changed.set('suite', next);
    } else {
      changed.delete('suite');
    }
    setParams(changed, { replace: true });
  };
  const ordered = CONTROL_ORDER.flatMap((control) => {
    const found = controls.find((score) => score.control === control);
    return found ? [found] : [];
  });
  const ready = view !== null && conclusions !== null;
  // V-23 of docs/showcase/영상전-검토.md: Contexa's count over every situation holds the attacks its sign-in check
  // refused before the AI judged; a named group is not stated, the refusals being counted over every situation.
  // L-39: its totals, as the server counted them for the chosen situations, say over how many runs the chart counts.
  const contexa = controls.find((score) => score.control === 'D') ?? null;
  const marked =
    conclusions !== null && QUESTIONS.some((question) => conclusions[question].controls.includes('C2'));
  return (
    <BenchScreen
      view="approaches"
      type="table"
      title={t('bench.chart.approaches.title')}
      purpose={t('bench.chart.approaches.guide')}
      more={ready ? <BenchDetailChip onClick={() => scores.show({ control: 'D' })} /> : null}
      sourceLine={
        ready ? <BenchSource text={t('frame.source.measured')} onOpen={() => method.show()} /> : null
      }
    >
      {state}
      {empty ? <p className={styles.line}>{t('bench.r7.empty')}</p> : null}
      {view && conclusions ? (
        <>
          {view.suites.length > 0 ? (
            <BenchChoice
              label={t('bench.r7.summary.suite')}
              value={suite?.suite ?? ''}
              onChange={chooseSuite}
            >
              <option value="">{t('bench.r7.suite.all')}</option>
              {view.suites.map((candidate) => (
                <option key={candidate.suite} value={candidate.suite}>
                  {t(`bench.r7.suite.${candidate.suite}`, { defaultValue: candidate.suite })}
                </option>
              ))}
            </BenchChoice>
          ) : null}
          <RateScatter
            points={ordered.map((score: ControlScore) => ({
              id: score.control,
              label: controlName(t, score.control),
              x: score.falseBlock,
              y: score.stoppedAny,
              emphasis: score.control === 'D',
            }))}
            xTitle={t('bench.chart.approaches.x')}
            yTitle={t('bench.chart.approaches.y')}
            summary={t('bench.chart.approaches.summary')}
            direction={t('bench.chart.approaches.direction')}
            legend={t('bench.chart.approaches.legend')}
            cross={t('bench.chart.approaches.cross')}
            basis={
              contexa
                ? t('bench.chart.approaches.basis', {
                    attacks: contexa.stoppedAny.total,
                    normals: contexa.falseBlock.total,
                  })
                : undefined
            }
          />
          {suite === null && contexa && view.judgmentTiming.STATIC_REFUSAL > 0 ? (
            <p className={styles.note}>
              {t('bench.r7.approaches.staticNote', {
                hits: contexa.stoppedAny.hits,
                total: contexa.stoppedAny.total,
                count: view.judgmentTiming.STATIC_REFUSAL,
              })}
            </p>
          ) : null}
          <ul className={styles.questions} aria-label={t('bench.r7.summary.questions')}>
            {QUESTIONS.map((question) => {
              const pick = conclusions[question];
              return (
                <li key={question} className={styles.question} data-question={question}>
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
          {marked ? <p className={styles.note}>{t('bench.r7.footnote')}</p> : null}
        </>
      ) : null}
    </BenchScreen>
  );
}
