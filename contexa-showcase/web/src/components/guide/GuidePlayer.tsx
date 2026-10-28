import { useCallback, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { GuideVideo } from '../../api/guides';
import { useNarrow } from '../../hooks/useNarrow';
import { guideEntry, type GuideId } from './guideConfig';
import styles from './GuidePlayer.module.css';

/** The words of the caption the browser is showing at this moment; empty when it shows none. */
function showingCue(video: HTMLVideoElement): string {
  const tracks = video.textTracks as TextTrackList | undefined;
  if (!tracks) {
    return '';
  }
  for (let index = 0; index < tracks.length; index += 1) {
    const track = tracks[index];
    if (track && track.mode === 'showing') {
      return Array.from(track.activeCues ?? [], (cue) => (cue as VTTCue).text).join(' ');
    }
  }
  return '';
}

interface GuidePlayerProps {
  readonly id: GuideId;
  readonly video: GuideVideo;
  readonly language: 'ko' | 'en';
  readonly onEnded: () => void;
}

/**
 * The video of a guide with its caption on a band under it (가이드영상-제작기획안.md 6절): the recorded screen is never
 * covered, so the band can be big and bold. The browser draws no caption of its own (the style hides it) and keeps the
 * tracks, so its caption menu still picks the language and turns captions off; the band follows the track that is showing.
 * Beside it: a thin bar of the scenes, the scene lines as a transcript that jumps to a scene, and a full screen for the
 * video and its band together.
 */
export function GuidePlayer({ id, video, language, onEnded }: GuidePlayerProps) {
  const { t } = useTranslation();
  const narrow = useNarrow();
  const player = useRef<HTMLDivElement>(null);
  const element = useRef<HTMLVideoElement>(null);
  const [caption, setCaption] = useState('');
  const [now, setNow] = useState(0);
  const entry = guideEntry(id);
  const scenes = video.scenes ?? [];
  const files = narrow && video.captionsNarrow ? video.captionsNarrow : video.captions;
  const canFullscreen = typeof document !== 'undefined' && document.fullscreenEnabled === true;

  const sync = useCallback(() => {
    const current = element.current;
    if (!current) {
      return;
    }
    setCaption(showingCue(current));
    setNow(current.currentTime);
  }, []);

  const jump = (start: number) => {
    const current = element.current;
    if (current) {
      current.currentTime = start;
      sync();
    }
  };

  const playing = scenes.reduce((found, scene, index) => (scene.start <= now ? index : found), -1);
  return (
    <>
      <div ref={player} className={styles.player} data-player>
        <video
          ref={element}
          className={styles.video}
          src={`/guides/${video.file}`}
          controls
          controlsList="nofullscreen"
          preload="metadata"
          onTimeUpdate={sync}
          onSeeked={sync}
          onLoadedData={sync}
          onEnded={onEnded}
        >
          {Object.entries(files).map(([lang, file]) => (
            <track
              key={lang}
              kind="captions"
              srcLang={lang}
              label={t(`guide.track.${lang}`)}
              src={`/guides/${file}`}
              default={lang === language}
            />
          ))}
        </video>
        {scenes.length > 0 ? (
          <div className={styles.bar} aria-hidden="true">
            {scenes.map((scene, index) => (
              <span
                key={scene.key}
                className={styles.scene}
                data-scene
                data-now={index === playing ? '' : undefined}
                style={{ flexGrow: (scenes[index + 1]?.start ?? video.durationSec) - scene.start }}
              />
            ))}
          </div>
        ) : null}
        <p className={styles.band} data-caption-band aria-hidden="true">
          {caption}
        </p>
      </div>
      {canFullscreen ? (
        <button
          type="button"
          className={styles.fullscreen}
          onClick={() => {
            void player.current?.requestFullscreen?.();
          }}
        >
          {t('guide.fullscreen')}
        </button>
      ) : null}
      <h3 className={styles.heading}>{t('guide.transcript')}</h3>
      <ol className={styles.lines}>
        {entry.scenes.map((key) => {
          const start = scenes.find((scene) => scene.key === key)?.start;
          return (
            <li key={key}>
              {start === undefined ? (
                t(key)
              ) : (
                <button type="button" className={styles.line} onClick={() => jump(start)}>
                  {t(key)}
                </button>
              )}
            </li>
          );
        })}
      </ol>
    </>
  );
}
