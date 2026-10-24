import { useTranslation } from 'react-i18next';
import { useBenchmark, type BenchmarkCase } from '../../api/benchmark';
import { MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { THEMES } from '../../components/main/themes';
import { MAIN_CASES } from './mainCases';
import styles from './IntroMapPage.module.css';

/**
 * The topics after the start by group number (설계서 1-2, IN-6, docs/agent A7-3): the three themes, then trying and
 * the summary.
 */
const TOPICS = [2, 3, 4, 5, 6, 7, 8] as const;
type Topic = (typeof TOPICS)[number];

/** The groups that tell each theme (IN-6): the stolen account over three groups, the insider and the agent in one each. */
const THEME_GROUPS: Readonly<Record<(typeof THEMES)[number]['id'], readonly Topic[]>> = {
  outside: [2, 3, 4],
  inside: [5],
  agent: [6],
};

/** The groups after the three themes: shaking the conditions yourself, then the summary. */
const AFTER: readonly Topic[] = [7, 8];

/** Contexa's right runs of a case over its scored runs in the current measurement ("측정 5/5"). */
function measuredLine(
  t: ReturnType<typeof useTranslation>['t'],
  found: BenchmarkCase | undefined,
): string | null {
  const cell = found?.cells.D;
  return cell ? t('main.1-2.badge.measured', { right: cell.right, counted: cell.counted }) : null;
}

/**
 * 1-2, what the demo checks (설계서 1-2, IN-6): the topics with what you try and what you will know, set under the two
 * themes they tell (the stolen account, where only the account is real; the insider, where everything is), then trying
 * and the summary. Each topic's cover opens it and passes what it found to the next topic's question. The badges are
 * the measurement's own counts: Contexa's right runs of the case each try sends, and the runs of the whole measurement.
 */
export default function IntroMapPage() {
  const { t } = useTranslation();
  const benchmark = useBenchmark(null);
  const cases = benchmark.data?.cases ?? [];
  const runs = benchmark.data?.scope.runs ?? null;
  const badges: Readonly<Record<Topic, string | null>> = {
    2: measuredLine(
      t,
      cases.find((found) => found.key === MAIN_CASES.attacker),
    ),
    3: t('main.1-2.badge.records'),
    4: measuredLine(
      t,
      cases.find((found) => found.key === MAIN_CASES.owner),
    ),
    5: measuredLine(
      t,
      cases.find((found) => found.key === MAIN_CASES.insider),
    ),
    // docs/agent A7-3: the agent case is in no measurement protocol; its card has no measured badge.
    6: null,
    7: runs === null ? null : t('main.1-2.badge.runs', { runs }),
    8: t('main.1-2.badge.cost'),
  };
  const card = (group: Topic) => (
    <li
      key={group}
      className={styles.topic}
      style={{ animationDelay: `calc(var(--map-step) * ${TOPICS.indexOf(group)})` }}
    >
      <div className={styles.head}>
        <span className={styles.number} aria-hidden="true">
          {group}
        </span>
        <b className={styles.name}>{t(`group.${group}`)}</b>
      </div>
      <p className={styles.label}>{t('main.1-2.try')}</p>
      <p className={styles.text}>{t(`main.1-2.${group}.try`)}</p>
      <p className={styles.label}>{t('main.1-2.learn')}</p>
      <p className={styles.learn}>{t(`main.1-2.${group}.learn`)}</p>
      <div className={styles.badge}>
        {badges[group] ? <SourceBadge kind="repeated" label={badges[group] ?? ''} /> : null}
      </div>
    </li>
  );
  return (
    <MainScreen title={t('main.1-2.title')} intro={t('main.1-2.intro')}>
      <div className={styles.themes}>
        {THEMES.map((theme) => (
          <section
            key={theme.id}
            className={styles.theme}
            data-theme={theme.id}
            aria-labelledby={`theme-${theme.id}`}
          >
            <p id={`theme-${theme.id}`} className={styles.themeHead}>
              <b className={styles.themeName}>{t(`theme.${theme.id}.name`)}</b>
              <span className={styles.themeLine}>{t(`theme.${theme.id}.line`)}</span>
            </p>
            <ol className={styles.topics} data-count={THEME_GROUPS[theme.id].length}>
              {THEME_GROUPS[theme.id].map(card)}
            </ol>
          </section>
        ))}
      </div>
      <ol className={styles.topics} data-count={AFTER.length} aria-label={t('main.1-2.after')}>
        {AFTER.map(card)}
      </ol>
    </MainScreen>
  );
}
