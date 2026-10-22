import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useBenchmark } from '../../api/benchmark';
import { useActEnd } from '../../api/journey';
import { usePromptQuality } from '../../api/promptQuality';
import { usePublicSettings } from '../../api/settings';
import { useTeasers, type TeaserKey, type TeasersView } from '../../api/teasers';
import { SourceLine } from '../../components/journey/FrameParts';
import { DifferenceMark } from '../../components/journey/JourneyParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { Icon } from '../../components/Icon';
import { DEFAULT_ROUTE, DIFFERENCES, type Difference } from '../../journey/journey';
import { count, seconds } from '../../journey/format';
import { useJourneyPlace } from '../../journey/useJourneyPlace';
import styles from './RecapPage.module.css';

/** The screen where each difference is seen first on the route (the screens that mark it seen). */
const SEEN_AT: Readonly<Record<Difference, string>> = {
  1: '1-3',
  2: '1-1',
  3: '2-3',
  4: '1-5',
  5: '1-6',
  6: '3-3',
};

function pathOf(number: string): string {
  return DEFAULT_ROUTE.find((screen) => screen.number === number)?.path ?? '/';
}

/** A measured value of a teaser record (portal TeaserService); null when the record has none or it is not a number. */
function value(teasers: TeasersView | undefined, key: TeaserKey, name: string): number | null {
  const item = teasers?.teasers.find((candidate) => candidate.key === key);
  const raw = item && !item.missing ? item.values[name] : null;
  return typeof raw === 'number' ? raw : null;
}

function holds(teasers: TeasersView | undefined, key: TeaserKey): boolean | null {
  return teasers?.teasers.find((candidate) => candidate.key === key)?.holds ?? null;
}

interface Measures {
  readonly decisions: number | null;
  readonly learned: number | null;
  readonly departures: number | null;
  readonly contexaBlocked: number | null;
  readonly ruleBlocked: number | null;
  readonly normal: number | null;
  readonly reasons: { readonly hits: number; readonly total: number } | null;
  readonly conditions: number | null;
  readonly reissueMs: number | null;
  readonly reissueHolds: boolean;
  readonly resumed: number | null;
  readonly from: number | null;
  readonly to: number | null;
  readonly grew: boolean;
}

/** A stored number, or null when the record holds none. */
function numberOf(raw: unknown): number | null {
  return typeof raw === 'number' ? raw : null;
}

/**
 * Each difference's one measured line (the old core-value cards' line), every number a server value. A line whose
 * value the record does not hold says so; a sentence whose fact the record does not make true takes its other words.
 */
function measuredLine(t: TFunction, language: string, difference: Difference, m: Measures): string | null {
  const n = (raw: number) => count(raw, language);
  switch (difference) {
    case 1:
      return m.decisions === null ? null : t('p5.recap.measure.1', { decisions: n(m.decisions) });
    case 2:
      return m.learned === null || m.departures === null
        ? null
        : t('p5.recap.measure.2', { learned: n(m.learned), departures: n(m.departures) });
    case 3:
      return m.contexaBlocked === null || m.ruleBlocked === null || m.normal === null
        ? null
        : t('p5.recap.measure.3', {
            contexa: n(m.contexaBlocked),
            numberRule: n(m.ruleBlocked),
            normal: n(m.normal),
          });
    case 4:
      if (m.reasons) {
        return t('p5.recap.measure.4.quality', { hits: n(m.reasons.hits), total: n(m.reasons.total) });
      }
      return m.conditions === null ? null : t('p5.recap.measure.4', { n: n(m.conditions) });
    case 5:
      if (m.resumed === null) {
        return null;
      }
      return m.reissueHolds && m.reissueMs !== null
        ? t('p5.recap.measure.5', { seconds: seconds(m.reissueMs), resumed: n(m.resumed) })
        : t('p5.recap.measure.5.fallback', { resumed: n(m.resumed) });
    case 6:
      if (m.from === null || m.to === null) {
        return null;
      }
      return t(m.grew ? 'p5.recap.measure.6' : 'p5.recap.measure.6.flat', { from: n(m.from), to: n(m.to) });
  }
}

/**
 * Screen 5-2, the six differences (화면재편-기획안 7절, T8): one card per difference with the line this demo measured for
 * it; pressing a card leads back to the screen where it is seen. A difference the visitor has not seen yet keeps its
 * question and says so, and its card leads to the screen that shows it. The identity line closes the screen (8절).
 * The run table, the core-value cards and the quiz are gone: the cards do their work.
 */
export default function RecapPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const place = useJourneyPlace();
  const benchmark = useBenchmark(null);
  const teasers = useTeasers().data;
  const settings = usePublicSettings();
  // The reasons that matched the facts they cite, from the published prompt-quality batch (U-7).
  const quality = usePromptQuality(null).data ?? null;
  const seen = new Set(place.differences);
  // Difference 6 reads the learned requests at the start and the end of try 3, as 3-3 and its wrap-up do (act-end 3).
  const learning = useActEnd(3, true).data ?? null;
  const learnedFrom = numberOf(learning?.values['from']);
  const learnedTo = numberOf(learning?.values['to']);
  const measures: Measures = {
    decisions: benchmark.data?.engine?.decisions ?? null,
    learned: value(teasers, 'FOLLOW_LEARNED', 'learned'),
    departures: value(teasers, 'E1_RESULT_FACTS', 'departures'),
    contexaBlocked: value(teasers, 'LEARN_AFTER_FALSE_BLOCKS', 'contexa'),
    ruleBlocked: value(teasers, 'LEARN_AFTER_FALSE_BLOCKS', 'numberRule'),
    normal: value(teasers, 'LEARN_AFTER_FALSE_BLOCKS', 'normalRuns'),
    reasons: quality ? { hits: quality.reasonMatch.hits, total: quality.reasonMatch.total } : null,
    conditions: settings.data?.engine.inspectorConditions ?? null,
    reissueMs: value(teasers, 'G_RULES_RESUME', 'reissueMs'),
    reissueHolds: holds(teasers, 'G_RULES_RESUME') === true,
    resumed: value(teasers, 'CHALLENGE_OUTCOMES', 'resumed'),
    from: learnedFrom,
    to: learnedTo,
    grew: learnedFrom !== null && learnedTo !== null && learnedTo > learnedFrom,
  };
  const lines = new Map(
    DIFFERENCES.map((difference) => [difference, measuredLine(t, language, difference, measures)] as const),
  );
  const measured = DIFFERENCES.some((difference) => seen.has(difference) && lines.get(difference) !== null);

  return (
    <RouteScreen
      title={t('screen.5-2.title')}
      purpose={t('screen.5-2.guide')}
      sourceLine={measured ? <SourceLine kind="measured" /> : null}
    >
      <ol className={styles.cards} aria-label={t('difference.cards.title')} data-count="exempt">
        {DIFFERENCES.map((difference) => {
          const isSeen = seen.has(difference);
          return (
            <li key={difference} className={styles.item}>
              <Link to={pathOf(SEEN_AT[difference])} className={styles.card} data-seen={isSeen || undefined}>
                <span className={styles.name}>
                  <DifferenceMark difference={difference} seen={isSeen} />
                  <span>{t(isSeen ? `difference.${difference}` : `difference.question.${difference}`)}</span>
                </span>
                <span className={styles.line}>
                  {isSeen ? (lines.get(difference) ?? t('p5.recap.measure.none')) : t('p5.recap.unseen')}
                </span>
                <span className={styles.go}>
                  <span className={styles.hidden}>{t(isSeen ? 'difference.back' : 'p5.recap.go')}</span>
                  <Icon name="chevronRight" className={styles.goIcon} />
                </span>
              </Link>
            </li>
          );
        })}
      </ol>
      <p className={styles.identity}>{t('identity.line')}</p>
    </RouteScreen>
  );
}
