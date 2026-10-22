import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useEngineActions } from '../../api/engine';
import { useActEnd } from '../../api/journey';
import { useStats } from '../../api/queries';
import { PartWrap } from '../../components/journey/Cards';
import { routeFlow } from '../../components/journey/flow';
import { SourceLine } from '../../components/journey/FrameParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { StateScreen } from '../../components/StateScreen';
import { VerdictChip } from '../../components/VerdictChip';
import { actEndSentence } from '../../journey/copy';
import { count } from '../../journey/format';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import styles from './FollowPage.module.css';
import { ReleaseRecord } from './ReleaseRecord';

const VERDICTS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'] as const;

type Verdict = (typeof VERDICTS)[number];

/** How long a judgment holds, as the engine publishes it: seconds or whole minutes; null while it holds until lifted. */
function holdTime(t: TFunction, seconds: number | null | undefined, language: string): string | null {
  if (seconds === null || seconds === undefined) {
    return null;
  }
  return seconds % 60 === 0
    ? t('p2.follow.time.minutes', { n: count(seconds / 60, language) })
    : t('p2.follow.time.seconds', { n: count(seconds, language) });
}

/**
 * What the hold does for each judgment (V-50): an allow is not judged again on the same connection for its time, a
 * check waits for the code, a review holds the requests; a judgment without a time holds until it is lifted.
 */
function holdLine(t: TFunction, verdict: Verdict, time: string | null): string {
  return time === null ? t('p2.follow.hold.none') : t(`p2.follow.hold.${verdict}`, { time });
}

/**
 * Screen 2-6, what follows each judgment (화면재편 T7), and 2-7, the part's wrap-up. The map is four rows, one per
 * judgment: how long it holds (the engine's published value), what happens next, and one line of how often Contexa
 * made it in this demo (forced runs left out, counted on the server). The block row adds how many reviews ran past
 * their time limit and were blocked, the fact its "past the time limit" step rests on. One plain line under the rows
 * says what the map shows; the identity checks' outcomes and the overlap rule are left to the decision details.
 */
export default function FollowPage({ ending }: { readonly ending: boolean }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const position = useJourneyPosition();
  const actions = useEngineActions();
  const stats = useStats();
  const actEnd = useActEnd(2, ending);

  if (ending) {
    return (
      <PartWrap
        sentence={
          actEnd.data && actEnd.data.source !== 'NONE' ? actEndSentence(t, language, actEnd.data) : null
        }
        measured={actEnd.data?.source === 'MEASUREMENT'}
        differences={position.differences}
      />
    );
  }

  const flow = routeFlow(t, position);
  const decided = stats.data?.engineActions ?? null;
  const ready = decided !== null && actions.data !== undefined;

  return (
    <RouteScreen
      title={t('screen.2-6.title')}
      purpose={t('screen.2-6.guide')}
      sourceLine={ready ? <SourceLine kind="tally" /> : null}
      back={flow.back}
      main={flow.next}
    >
      {stats.isPending || actions.isPending ? <StateScreen kind="loading" /> : null}
      {ready ? (
        <ol className={styles.rows}>
          {VERDICTS.map((verdict) => {
            const time = holdTime(t, actions.data?.[verdict]?.ttlSeconds, language);
            return (
              <li key={verdict} className={styles.row} data-verdict={verdict}>
                <span className={styles.head}>
                  <VerdictChip verdict={verdict} />
                  <span className={styles.hold}>{holdLine(t, verdict, time)}</span>
                </span>
                <span className={styles.next}>
                  {t(`p2.follow.next.${verdict}`, { time: time ?? t('p2.follow.time.hold') })}
                </span>
                {/* Each count names its judgment (V-16); the block row sets its two kinds side by side (V-15). */}
                <span className={styles.count}>
                  {verdict === 'BLOCK'
                    ? t('p2.follow.blockCount', {
                        n: count(decided.BLOCK ?? 0, language),
                        promoted: count(stats.data?.blockedAfterReview ?? 0, language),
                      })
                    : t(`p2.follow.count.${verdict}`, { n: count(decided[verdict] ?? 0, language) })}
                </span>
              </li>
            );
          })}
        </ol>
      ) : null}
      <p className={styles.line}>{t('p2.follow.line')}</p>
      <ReleaseRecord />
    </RouteScreen>
  );
}
