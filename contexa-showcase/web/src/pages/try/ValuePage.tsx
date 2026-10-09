import { useTranslation } from 'react-i18next';
import { useBenchmark } from '../../api/benchmark';
import { usePublicSettings } from '../../api/settings';
import { useTeasers, type TeaserKey, type TeasersView } from '../../api/teasers';
import { ActionChip } from '../../components/common/ActionChip';
import { SourceMark } from '../../components/common/SourceMark';
import { DifferenceMark } from '../../components/journey/JourneyParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { DIFFERENCES } from '../../journey/journey';
import { count, seconds } from '../../journey/format';
import styles from './ValuePage.module.css';

/** A measured value of a teaser record (portal TeaserService); null when the record has none. */
function value(teasers: TeasersView | undefined, key: TeaserKey, name: string): unknown {
  const item = teasers?.teasers.find((candidate) => candidate.key === key);
  return item && !item.missing ? (item.values[name] ?? null) : null;
}

function holds(teasers: TeasersView | undefined, key: TeaserKey): boolean | null {
  return teasers?.teasers.find((candidate) => candidate.key === key)?.holds ?? null;
}

/**
 * The core value (value, 7.4): Contexa is more than a security tool, in six cards with the same names and order as the
 * six differences, each with one line measured by this demo, and the honest conclusion: every attack it judged risky
 * was stopped, and the ones it judged allowable were missed, with why in the limits. Every number is a server value;
 * a sentence whose fact the record does not hold is replaced by its fallback (plan 8절).
 */
export default function ValuePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const benchmark = useBenchmark(null);
  const settings = usePublicSettings();
  const teasers = useTeasers().data;
  const number = (raw: unknown) => (typeof raw === 'number' ? count(raw, language) : '-');
  const reissueMs = value(teasers, 'G_RULES_RESUME', 'reissueMs');
  const resumed = number(value(teasers, 'CHALLENGE_OUTCOMES', 'resumed'));
  const measures: Readonly<Record<number, string>> = {
    1: t('value.measure.1', { decisions: number(benchmark.data?.engine?.decisions ?? null) }),
    2: t('value.measure.2', {
      learned: number(value(teasers, 'FOLLOW_LEARNED', 'learned')),
      departures: number(value(teasers, 'E1_RESULT_FACTS', 'departures')),
    }),
    3: t('value.measure.3', {
      contexa: number(value(teasers, 'LEARN_AFTER_FALSE_BLOCKS', 'contexa')),
      numberRule: number(value(teasers, 'LEARN_AFTER_FALSE_BLOCKS', 'numberRule')),
      normal: number(value(teasers, 'LEARN_AFTER_FALSE_BLOCKS', 'normalRuns')),
    }),
    4: t('value.measure.4', { n: number(settings.data?.engine.inspectorConditions ?? null) }),
    5:
      holds(teasers, 'G_RULES_RESUME') === true && typeof reissueMs === 'number'
        ? t('value.measure.5', { seconds: seconds(reissueMs), resumed })
        : t('value.measure.5.fallback', { resumed }),
    6: t('value.measure.6', {
      from: number(value(teasers, 'SYNC_WHEN_OBSERVATIONS', 'from')),
      to: number(value(teasers, 'SYNC_WHEN_OBSERVATIONS', 'to')),
    }),
  };
  const judged = {
    judged: number(value(teasers, 'RISK_JUDGED_STOPPED', 'judged')),
    stopped: number(value(teasers, 'RISK_JUDGED_STOPPED', 'stopped')),
    missed: number(value(teasers, 'RISK_JUDGED_STOPPED', 'judgedAllowMissed')),
  };
  const setting = benchmark.data?.spec?.settingHash.slice(0, 8) ?? '-';
  return (
    <RouteScreen
      title={t('value.title')}
      purpose={t('value.purpose')}
      source={
        <SourceMark kind="MEASUREMENT" measured>
          {t('value.source', { setting })}
        </SourceMark>
      }
      nextLabel={t('value.next')}
      more={
        <ActionChip to="/benchmark/limits" icon="chart" variant="open">
          {t('value.limits')}
        </ActionChip>
      }
    >
      <ol className={styles.cards} aria-label={t('value.title')}>
        {DIFFERENCES.map((difference) => (
          <li key={difference} className={styles.card}>
            <span className={styles.name}>
              <DifferenceMark difference={difference} seen />
              {t(`value.name.${difference}`)}
            </span>
            <span className={styles.what}>{t(`value.what.${difference}`)}</span>
            <span className={styles.measure}>{measures[difference]}</span>
          </li>
        ))}
      </ol>
      <p className={styles.conclusion}>
        {holds(teasers, 'RISK_JUDGED_STOPPED') === true
          ? t('value.conclusion', judged)
          : t('value.conclusionFallback', judged)}
      </p>
    </RouteScreen>
  );
}
