import { useTranslation } from 'react-i18next';
import { useBenchmark, type BenchmarkView, type ControlScore } from '../../api/benchmark';
import { ActionChip } from '../../components/common/ActionChip';
import { SourceMark } from '../../components/common/SourceMark';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import styles from './DilemmaPage.module.css';

const RULE_BLIND = 'RULE_BLIND';

interface Figure {
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
 * The rules' dilemma (dilemma, 7.4): on the same cases, the number rule blocks normal work and still misses attacks,
 * the business record rule stops what it was written for and misses what it was not, and Contexa blocks no normal
 * work and stops every attack it judged risky. Each figure is the benchmark's count (the server's); the conclusion band
 * is shown only while the record says what it states.
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
  // The band says Contexa kept normal work going (blocked none) and stopped every attack it judged risky.
  const holds =
    d !== null &&
    judged !== null &&
    d.falseBlock.hits === 0 &&
    judged.runs > 0 &&
    judged.stopped === judged.runs;
  const columns: readonly { readonly control: string; readonly figures: readonly Figure[] }[] =
    c1 && c2 && d && judged
      ? [
          {
            control: 'C1',
            figures: [
              {
                value: c1.falseBlock.hits,
                label: t('dilemma.normalBlocked'),
                tone: c1.falseBlock.hits > 0 ? 'bad' : 'good',
              },
              { value: c1.missed, label: t('dilemma.attacksMissed'), tone: c1.missed > 0 ? 'bad' : 'good' },
            ],
          },
          {
            control: 'C2',
            figures: [
              { value: c2.stopped.hits, label: t('dilemma.attacksStopped'), tone: 'good' },
              {
                value: blindC2?.missed ?? 0,
                label: t('dilemma.blindMissed'),
                tone: (blindC2?.missed ?? 0) > 0 ? 'bad' : 'good',
              },
            ],
          },
          {
            control: 'D',
            figures: [
              {
                value: d.falseBlock.hits,
                label: t('dilemma.normalBlocked'),
                tone: d.falseBlock.hits > 0 ? 'bad' : 'good',
              },
              {
                value: judged.stopped,
                label:
                  judged.stopped === judged.runs
                    ? t('dilemma.judgedAll')
                    : t('dilemma.judgedSome', { runs: count(judged.runs, language) }),
                tone: 'good',
              },
            ],
          },
        ]
      : [];

  return (
    <RouteScreen
      title={t('dilemma.title', { cases: view ? count(view.scope.cases, language) : '-' })}
      purpose={t('dilemma.purpose')}
      source={
        view ? (
          <SourceMark kind="MEASUREMENT" measured>
            {t('dilemma.source', {
              setting: view.spec?.settingHash.slice(0, 8) ?? '-',
              runs: count(view.scope.runs, language),
            })}
          </SourceMark>
        ) : null
      }
      more={
        <ActionChip to="/lab" icon="search" variant="open">
          {t('dilemma.tighten')}
        </ActionChip>
      }
    >
      {benchmark.isPending ? <StateScreen kind="loading" /> : null}
      <div className={styles.columns}>
        {columns.map((column) => (
          <section
            key={column.control}
            className={styles.column}
            data-contexa={column.control === 'D' || undefined}
            aria-labelledby={`dilemma-${column.control}`}
          >
            <h2 id={`dilemma-${column.control}`} className={styles.name}>
              {t(`control.${column.control}.name`)}
              {column.control === 'C2' ? '*' : ''}
            </h2>
            <dl className={styles.figures}>
              {column.figures.map((figure) => (
                <div key={figure.label} className={styles.figure} data-tone={figure.tone}>
                  <dt className={styles.figureLabel}>{figure.label}</dt>
                  <dd className={styles.figureValue}>{count(figure.value, language)}</dd>
                </div>
              ))}
            </dl>
            <p className={styles.meaning}>{t(`dilemma.meaning.${column.control}`)}</p>
          </section>
        ))}
      </div>
      {columns.length > 0 ? (
        <div className={styles.notes}>
          {(blindD?.missed ?? 0) > 0 ? (
            <p>{t('dilemma.alsoMissed', { n: count(blindD?.missed ?? 0, language) })}</p>
          ) : null}
          <p>{t('hook.note')}</p>
        </div>
      ) : null}
      {columns.length > 0 ? (
        <p className={styles.conclusion}>
          {holds
            ? t('dilemma.conclusion')
            : t('dilemma.conclusionFallback', {
                blocked: count(d?.falseBlock.hits ?? 0, language),
                judged: count(judged?.runs ?? 0, language),
                stopped: count(judged?.stopped ?? 0, language),
              })}
        </p>
      ) : null}
    </RouteScreen>
  );
}
