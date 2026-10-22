import { useTranslation } from 'react-i18next';
import { useBenchmark, type BenchmarkView, type ControlScore } from '../../api/benchmark';
import { SourceLine } from '../../components/journey/FrameParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import styles from './DilemmaPage.module.css';

const RULE_BLIND = 'RULE_BLIND';

interface Figure {
  readonly key: string;
  readonly value: number;
  readonly label: string;
  /** Good news for the business (green) or bad (red). */
  readonly tone: 'good' | 'bad';
}

function score(view: BenchmarkView, control: string, suite?: string): ControlScore | null {
  const controls = suite ? view.suites.find((entry) => entry.suite === suite)?.controls : view.controls;
  return controls?.find((entry) => entry.control === control) ?? null;
}

/**
 * The one sentence over the columns, picked from the benchmark's own counts so it says only what they hold: whether
 * Contexa stopped normal work, whether it stopped every attack it judged risky (none judged risky is said as such),
 * and, where the first part does not already say so, that some attacks got through.
 */
function sentence(
  contexa: ControlScore,
  blind: ControlScore | null,
  judged: BenchmarkView['riskJudged'],
): readonly string[] {
  const clean = contexa.falseBlock.hits === 0;
  const missed = contexa.missed > 0 || (blind?.missed ?? 0) > 0 ? ['p5.dilemma.missed'] : [];
  if (judged.runs === 0) {
    return [clean ? 'p5.dilemma.sentence.noJudgedClean' : 'p5.dilemma.sentence.noJudgedBlocked', ...missed];
  }
  if (judged.stopped === judged.runs) {
    return [clean ? 'p5.dilemma.sentence.clean' : 'p5.dilemma.sentence.blocked', ...missed];
  }
  // Some attacks judged risky got through: the sentence already says attacks got through.
  return [clean ? 'p5.dilemma.sentence.some' : 'p5.dilemma.sentence.both'];
}

/**
 * Screen 5-1, the numbers on the same situations (화면재편-기획안 7절, T5): one sentence the benchmark's counts pick,
 * then three columns of two large numbers each. Time and volume limits: normal work stopped and attacks missed;
 * approval and owner check: attacks stopped and those missed where no rule was written; Contexa: normal work stopped
 * and attacks stopped of those it judged risky. Every number is the benchmark's (the server's); one source line.
 */
export default function DilemmaPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const benchmark = useBenchmark(null);
  const view = benchmark.data ?? null;
  const c1 = view ? score(view, 'C1') : null;
  const c2 = view ? score(view, 'C2') : null;
  const d = view ? score(view, 'D') : null;
  const blindC2 = view ? score(view, 'C2', RULE_BLIND) : null;
  const blindD = view ? score(view, 'D', RULE_BLIND) : null;
  const judged = view?.riskJudged ?? null;
  const ready = c1 !== null && c2 !== null && d !== null && judged !== null;
  const tone = (bad: boolean): Figure['tone'] => (bad ? 'bad' : 'good');
  const columns: readonly { readonly control: string; readonly figures: readonly Figure[] }[] = ready
    ? [
        {
          control: 'C1',
          figures: [
            {
              key: 'normal',
              value: c1.falseBlock.hits,
              label: t('p5.dilemma.normalBlocked'),
              tone: tone(c1.falseBlock.hits > 0),
            },
            {
              key: 'missed',
              value: c1.missed,
              label: t('p5.dilemma.attacksMissed'),
              tone: tone(c1.missed > 0),
            },
          ],
        },
        {
          control: 'C2',
          figures: [
            { key: 'stopped', value: c2.stopped.hits, label: t('p5.dilemma.attacksStopped'), tone: 'good' },
            {
              key: 'blind',
              value: blindC2?.missed ?? 0,
              label: t('p5.dilemma.blindMissed'),
              tone: tone((blindC2?.missed ?? 0) > 0),
            },
          ],
        },
        {
          control: 'D',
          figures: [
            {
              key: 'normal',
              value: d.falseBlock.hits,
              label: t('p5.dilemma.normalBlocked'),
              tone: tone(d.falseBlock.hits > 0),
            },
            {
              key: 'judged',
              value: judged.stopped,
              label:
                judged.runs > 0 && judged.stopped === judged.runs
                  ? t('p5.dilemma.judgedAll')
                  : t('p5.dilemma.judgedSome', { runs: count(judged.runs, language) }),
              tone: tone(judged.stopped < judged.runs),
            },
          ],
        },
      ]
    : [];

  return (
    <RouteScreen
      title={t('screen.5-1.title')}
      purpose={t('screen.5-1.guide')}
      sourceLine={ready ? <SourceLine kind="measured" /> : null}
    >
      {benchmark.isPending ? <StateScreen kind="loading" /> : null}
      {!benchmark.isPending && !ready ? <StateScreen kind="notReady" /> : null}
      {ready ? (
        <p className={styles.sentence}>
          {sentence(d, blindD, judged)
            .map((key) => t(key))
            .join(' ')}
        </p>
      ) : null}
      {ready ? (
        <div className={styles.columns}>
          {columns.map((column) => (
            <section
              key={column.control}
              className={styles.column}
              data-contexa={column.control === 'D' || undefined}
              aria-labelledby={`dilemma-${column.control}`}
              data-block
            >
              <h2 id={`dilemma-${column.control}`} className={styles.name}>
                {t(`control.${column.control}.name`)}
                {column.control === 'C2' ? '*' : null}
              </h2>
              <dl className={styles.figures}>
                {column.figures.map((figure) => (
                  <div key={figure.key} className={styles.figure} data-tone={figure.tone}>
                    <dt className={styles.figureLabel}>{figure.label}</dt>
                    <dd className={styles.figureValue}>{count(figure.value, language)}</dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
      ) : null}
      {ready ? <p className={styles.note}>{t('p5.dilemma.note')}</p> : null}
    </RouteScreen>
  );
}
