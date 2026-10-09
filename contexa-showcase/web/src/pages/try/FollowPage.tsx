import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useEngineActions } from '../../api/engine';
import { useActEnd } from '../../api/journey';
import { useStats, useVisitor } from '../../api/queries';
import { useTeasers } from '../../api/teasers';
import { AppHeader } from '../../components/AppHeader';
import { SourceMark } from '../../components/common/SourceMark';
import { ActEndCard } from '../../components/journey/Cards';
import { routeFlow } from '../../components/journey/flow';
import { JourneyBar } from '../../components/journey/JourneyParts';
import { ActionBar, MoreRow, StepHeader } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { VerdictChip } from '../../components/VerdictChip';
import { actEndSentence, teaserCopy } from '../../journey/copy';
import { count, utcTime } from '../../journey/format';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import experience from './Experience.module.css';
import styles from './FollowPage.module.css';

const VERDICTS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'] as const;

/** A hold time as the engine published it: seconds, whole minutes, or none. */
function holdTime(t: TFunction, seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) {
    return t('follow.ttl.none');
  }
  return seconds % 60 === 0
    ? t('follow.ttl.minutes', { n: seconds / 60 })
    : t('follow.ttl.seconds', { n: seconds });
}

/**
 * F, the follow-up map (follow, 7.2), and the end of act 2 as a screen of its own (D-41). The map is one row per
 * decision: how long it holds (the core's default as the engine publishes it), what happens next, and how often the
 * engine decided it outside forced runs; the identity check row carries how the checks ended. Every number is counted
 * on the server.
 */
export default function FollowPage({ ending }: { readonly ending: boolean }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  useVisitor();
  const position = useJourneyPosition();
  const actions = useEngineActions();
  const stats = useStats();
  const teasers = useTeasers();
  const actEnd = useActEnd(2, ending);
  const next = position.next;

  if (ending) {
    return (
      <>
        <AppHeader />
        <main id="main" className={experience.page}>
          <JourneyBar />
          <ActEndCard
            act={2}
            differences={position.differences}
            sentence={
              actEnd.data && actEnd.data.source !== 'NONE' ? actEndSentence(t, language, actEnd.data) : null
            }
            measured={actEnd.data?.source === 'MEASUREMENT'}
            runId={actEnd.data?.runId ?? null}
            next={teaserCopy(t, language, 'FOLLOW_LEARNED', teasers.data, position.differences.length)}
            continueTo={next?.path ?? '/intro/learning'}
            back={{ to: '/try/follow', label: t('step.back', { step: t('place.step.follow') }) }}
            benchmarkTo="/benchmark"
            shareUrl={window.location.href}
          />
        </main>
      </>
    );
  }

  // "Next · act 2 wrap-up" on the default route; the concept path goes on to the timing screens (U-11).
  const flow = routeFlow(t, language, position, teasers.data, t('e2.next.end'), 'act-end-2');
  const outcomes = teasers.data?.teasers.find((teaser) => teaser.key === 'CHALLENGE_OUTCOMES') ?? null;
  const values = outcomes?.values ?? {};
  const byOutcome = (values['outcomes'] ?? {}) as Readonly<Record<string, number>>;
  const checks = typeof values['total'] === 'number' ? values['total'] : null;
  const decided = stats.data?.engineActions ?? null;

  return (
    <>
      <AppHeader />
      <main id="main" className={experience.page}>
        <JourneyBar />
        <div className={experience.step}>
          <StepHeader
            title={t('follow.title')}
            purpose={t('follow.purpose')}
            source={
              <SourceMark kind="ENGINE" measured>
                {t('follow.source', {
                  from: stats.data?.runs.firstAt ? utcTime(stats.data.runs.firstAt) : '-',
                  to: stats.data?.runs.lastAt ? utcTime(stats.data.runs.lastAt) : '-',
                })}
              </SourceMark>
            }
          />
          {stats.isPending || actions.isPending ? <StateScreen kind="loading" /> : null}
          {decided && actions.data ? (
            <ol className={styles.rows}>
              {VERDICTS.map((verdict) => (
                <li key={verdict} className={styles.row} data-verdict={verdict}>
                  <span className={styles.head}>
                    <VerdictChip verdict={verdict} />
                    <span className={styles.hold}>{holdTime(t, actions.data[verdict]?.ttlSeconds)}</span>
                  </span>
                  <span className={styles.next}>{t(`follow.next.${verdict}`)}</span>
                  <span className={styles.count}>
                    {verdict === 'BLOCK'
                      ? t('follow.blockCount', {
                          blocks: count(decided.BLOCK ?? 0, language),
                          releases: count(stats.data?.releases ?? 0, language),
                        })
                      : t('follow.count', { n: count(decided[verdict] ?? 0, language) })}
                  </span>
                  {verdict === 'CHALLENGE' && checks !== null ? (
                    <span className={styles.outcomes}>
                      {t('follow.outcomes', {
                        total: count(checks, language),
                        resumed: count(
                          typeof values['resumed'] === 'number' ? values['resumed'] : 0,
                          language,
                        ),
                        noMailbox: count(byOutcome['NO_MAILBOX'] ?? 0, language),
                        abandoned: count(byOutcome['ABANDONED'] ?? 0, language),
                        expired: count(byOutcome['EXPIRED'] ?? 0, language),
                        failed: count(byOutcome['FAILED'] ?? 0, language),
                      })}
                    </span>
                  ) : null}
                </li>
              ))}
            </ol>
          ) : null}
          <p className={experience.callout}>{t('follow.takeaway')}</p>
          <MoreRow>
            <details className={experience.more}>
              <summary>{t('follow.overlap')}</summary>
              <p className={experience.foldText}>{t('follow.overlapText')}</p>
            </details>
          </MoreRow>
          <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
        </div>
      </main>
    </>
  );
}
