import { useTranslation } from 'react-i18next';
import type { JudgmentTimingKind } from '../../api/benchmark';
import { ActionChip } from '../../components/common/ActionChip';
import { SourceMark } from '../../components/common/SourceMark';
import { NextLink } from '../../components/journey/StepParts';
import experience from '../try/Experience.module.css';
import { BenchScreen } from './BenchScreen';
import { useBenchView } from './benchData';
import { useBenchSetting } from './benchPlace';
import styles from './Bench.module.css';

const KINDS: readonly JudgmentTimingKind[] = [
  'STATIC_REFUSAL',
  'BEFORE_RESPONSE',
  'NEXT_REQUEST',
  'JUDGED_ALLOW',
  'OTHER',
];

/**
 * B1-2, judgment and timing (bench-judge, 7.8): how each attack run Contexa received ended, as one stacked bar the
 * server counted (refused by the permission check first, decided before the response, stopped from the next request
 * on, judged to allow, other), then what the two limits mean: the timing calls for the synchronous mode, the judgment
 * is shown with its reasons in the limits.
 */
export default function BenchJudgmentPage() {
  const { t } = useTranslation();
  const { search } = useBenchSetting();
  const { view, empty, state } = useBenchView();
  const timing = view?.judgmentTiming ?? null;
  const shown = KINDS.filter((kind) => kind !== 'OTHER' || (timing?.OTHER ?? 0) > 0);
  return (
    <BenchScreen
      view="judgment"
      title={
        view
          ? t('benchmark.judgment.title', { n: view.scope.attackRuns })
          : t('benchmark.judgment.titleLoading')
      }
      purpose={t('benchmark.judgment.purpose')}
      source={
        view ? (
          <SourceMark kind="MEASUREMENT" measured>
            {t('benchmark.judgment.source', {
              protocol: view.scope.protocols.map((protocol) => protocol.protocolId).join(', '),
            })}
          </SourceMark>
        ) : null
      }
      back={{ to: `/benchmark/cases${search}`, label: t('benchmark.toCases') }}
      main={<NextLink to={`/benchmark/limits${search}`} label={t('benchmark.toLimits')} />}
    >
      {state}
      {empty ? <p className={experience.lead}>{t('bench.empty')}</p> : null}
      {view && timing ? (
        <>
          <div className={styles.bar} role="img" aria-label={t('benchmark.judgment.barLabel')}>
            {shown.map((kind) =>
              timing[kind] > 0 ? (
                <span
                  key={kind}
                  className={styles.barPart}
                  data-kind={kind}
                  style={{ flexGrow: timing[kind] }}
                />
              ) : null,
            )}
          </div>
          <ul className={styles.legend}>
            {shown.map((kind) => (
              <li key={kind} className={styles.legendItem}>
                <span className={`${styles.swatch} ${styles.barPart}`} data-kind={kind} aria-hidden="true" />
                <span>{t(`benchmark.judgment.kind.${kind}`)}</span>
                <span className={styles.legendCount}>{t('benchmark.times', { n: timing[kind] })}</span>
              </li>
            ))}
          </ul>
          <div className={styles.callouts}>
            <p className={styles.callout}>
              <span>{t('benchmark.judgment.timing', { n: timing.NEXT_REQUEST })}</span>
              <ActionChip to="/try/timing/when" icon="arrowRight" size="sm" variant="open">
                {t('benchmark.judgment.toWhen')}
              </ActionChip>
            </p>
            <p className={styles.callout}>
              <span>{t('benchmark.judgment.judged', { n: timing.JUDGED_ALLOW })}</span>
            </p>
          </div>
          <p className={experience.lead}>
            {t('benchmark.judgment.risk', { runs: view.riskJudged.runs, stopped: view.riskJudged.stopped })}
          </p>
        </>
      ) : null}
    </BenchScreen>
  );
}
