import type { TFunction } from 'i18next';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useGuides, videoOf } from '../api/guides';
import { useVisitor } from '../api/queries';
import { AppHeader } from '../components/AppHeader';
import { TermScope } from '../components/common/Glossary';
import {
  GUIDE_IDS,
  guideEntry,
  guideGroup,
  guideScreenPath,
  type GuideGroup,
  type GuideId,
} from '../components/guide/guideConfig';
import { GuideWindow } from '../components/guide/GuideWindow';
import { useWatched } from '../components/guide/guideWatched';
import frame from '../components/main/MainScreen.module.css';
import route from '../journey/route.json';
import styles from './GuidesPage.module.css';

const GROUPS: readonly GuideGroup[] = ['S', 'H', 'A', 'C'];

/** The name of a screen a video explains: its own name, with the lane in front for the screens of the person's track. */
function screenName(t: TFunction, screen: string): string {
  if (screen === 'benchmark' || screen === 'lab') {
    return t(`frame.menu.${screen}`);
  }
  const name = t(`main.${screen}.name`, { defaultValue: screen });
  const lane = route.find((found) => found.number === screen)?.lane;
  return lane === 'attack' || lane === 'normal' || lane === 'insider' ? `${t(`lane.${lane}`)} · ${name}` : name;
}

/**
 * The list of the guide videos (가이드영상-제작기획안.md 4.1절): every recorded video in one place, for a newcomer first,
 * then those of the person's track, the agent's and the shared deeper ones. Each row names the video's length, whether this
 * browser watched it to the end, the screens it explains (each a link to that screen) and opens the same window the
 * screens open. The recordings made before the new flow are not listed.
 */
export default function GuidesPage() {
  const { t, i18n } = useTranslation();
  useVisitor();
  const guides = useGuides();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [playing, setPlaying] = useState<GuideId | null>(null);
  const videoIn = (id: GuideId) => videoOf(guides.data, id, language);
  const recorded = GUIDE_IDS.filter((id) => guideEntry(id).kind !== 'legacy' && videoIn(id));
  const playingVideo = playing === null ? undefined : videoIn(playing);
  return (
    <>
      <AppHeader />
      <main id="main" className={frame.page}>
        <TermScope>
          <div className={frame.inner}>
            <header className={frame.head} data-zone="title" data-block>
              <h1 className={frame.title}>{t('guides.title')}</h1>
              <p className={frame.intro} data-guide>
                {t('guides.intro')}
              </p>
            </header>
            <div className={frame.core} data-zone="body">
              {!guides.isPending && recorded.length === 0 ? <p className={styles.none}>{t('guides.none')}</p> : null}
              {GROUPS.map((group) => {
                const ids = recorded.filter((id) => guideGroup(id) === group);
                return ids.length === 0 ? null : (
                  <section key={group} className={styles.group}>
                    <h2 className={styles.groupName}>{t(`guides.group.${group}`)}</h2>
                    <ul className={styles.rows}>
                      {ids.map((id) => (
                        <GuideRow key={id} id={id} seconds={videoIn(id)?.durationSec ?? 0} onPlay={() => setPlaying(id)} />
                      ))}
                    </ul>
                  </section>
                );
              })}
            </div>
          </div>
        </TermScope>
      </main>
      {playing !== null && playingVideo ? (
        <GuideWindow id={playing} video={playingVideo} open onClose={() => setPlaying(null)} />
      ) : null}
    </>
  );
}

function GuideRow({ id, seconds, onPlay }: { readonly id: GuideId; readonly seconds: number; readonly onPlay: () => void }) {
  const { t } = useTranslation();
  const watched = useWatched(id);
  const entry = guideEntry(id);
  const length = Math.round(seconds);
  return (
    <li className={styles.row}>
      <div className={styles.text}>
        <b className={styles.name}>{t(entry.title)}</b>
        <span className={styles.meta}>
          {t('guides.length', { minutes: Math.floor(length / 60), seconds: length % 60 })}
          {watched ? <span className={styles.watched}>{` · ${t('guides.watched')}`}</span> : null}
        </span>
        {entry.screens.length > 0 ? (
          <ul className={styles.screens} aria-label={t('guides.screens')}>
            {entry.screens.map((screen) => {
              const path = guideScreenPath(screen);
              return path === null ? null : (
                <li key={screen}>
                  <Link to={path} className={styles.screen}>
                    {screenName(t, screen)}
                  </Link>
                </li>
              );
            })}
          </ul>
        ) : null}
      </div>
      <button type="button" className={styles.play} onClick={onPlay}>
        <span className={styles.playMark} aria-hidden="true" />
        {t('guides.play')}
      </button>
    </li>
  );
}
