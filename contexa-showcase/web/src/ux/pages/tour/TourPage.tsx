import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { useGuides } from '../../../api/guides';
import { HttpError } from '../../../api/http';
import { markWatched, useWatched } from '../../../components/guide/guideWatched';
import { formatNumber, formatUtc } from '../../format';
import { Badge, Card, EmptyState, ErrorState, Loading, Note, PageHead } from '../../ui';
import { useMedia } from '../../useMedia';
import styles from './Tour.module.css';
import { CURRENT_SCREENS, clock, videosIn, type Video } from './tour';

const PHONE_QUERY = '(width < 768px)';

/**
 * The product tour (기획안 4절, DEC-68): the recorded guide videos from the manifest the recording script writes, the
 * chosen one in a player that never starts by itself, with its captions in both languages and its scenes to jump to.
 */
export default function TourPage() {
  const { t, i18n } = useTranslation();
  const [params] = useSearchParams();
  const guides = useGuides();
  const language = i18n.language === 'en' ? 'en' : 'ko';
  const videos = videosIn(guides.data, language);
  const chosen = videos.find((video) => video.id === params.get('video')) ?? videos[0] ?? null;
  const missing = guides.error instanceof HttpError && guides.error.status === 404;
  const hrefOf = (id: string) => {
    const next = new URLSearchParams(params);
    next.set('video', id);
    return `?${next.toString()}`;
  };
  return (
    <>
      <PageHead title={t('ux.tour.title')} desc={t('ux.tour.desc')} />
      {guides.isPending ? (
        <Loading rows={4} />
      ) : guides.isError && !missing ? (
        <ErrorState onRetry={() => void guides.refetch()} />
      ) : chosen === null ? (
        <EmptyState>{t('ux.tour.none')}</EmptyState>
      ) : (
        <div className={styles.stack}>
          {videos.some((video) => video.screens !== CURRENT_SCREENS) ? (
            <Note icon="info">{t('ux.tour.earlier')}</Note>
          ) : null}
          <div className={styles.layout}>
            <Player key={chosen.id} video={chosen} />
            <Card title={t('ux.tour.list')} flush>
              <ul className={styles.list}>
                {videos.map((video) => (
                  <li key={video.id}>
                    <Link
                      to={hrefOf(video.id)}
                      replace
                      className={styles.item}
                      aria-current={video.id === chosen.id ? 'true' : undefined}
                    >
                      <VideoLine video={video} />
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          </div>
        </div>
      )}
    </>
  );
}

/** A video's title from the dictionary, or its id for a video the dictionary does not name yet. */
function useTitle(id: string): string {
  const { t, i18n } = useTranslation();
  const key = `ux.tour.video.${id}.title`;
  return i18n.exists(key) ? t(key) : id;
}

function VideoLine({ video }: { readonly video: Video }) {
  const { t, i18n } = useTranslation();
  const watched = useWatched(video.id);
  const title = useTitle(video.id);
  const n = (value: number) => formatNumber(value, i18n.language);
  const whole = Math.round(video.durationSec);
  return (
    <span className={styles.itemBody}>
      <span className={styles.itemTitle}>{title}</span>
      <span className={styles.itemMeta}>
        <span>{t('ux.tour.duration', { m: n(Math.floor(whole / 60)), s: n(whole % 60) })}</span>
        <span>{t('ux.tour.recorded', { time: formatUtc(video.recordedAt).slice(0, 10), zone: t('ux.time.zone') })}</span>
      </span>
      {video.screens !== CURRENT_SCREENS || watched ? (
        <span className={styles.itemBadges}>
          {video.screens !== CURRENT_SCREENS ? <Badge tone="line">{t('ux.tour.earlierBadge')}</Badge> : null}
          {watched ? (
            <Badge tone="allow" icon="check">
              {t('ux.tour.watched')}
            </Badge>
          ) : null}
        </span>
      ) : null}
    </span>
  );
}

/** The chosen video: no autoplay, the captions of both languages (the screen's first, a phone's shorter lines), its scenes. */
function Player({ video }: { readonly video: Video }) {
  const { t, i18n } = useTranslation();
  const phone = useMedia(PHONE_QUERY);
  const ref = useRef<HTMLVideoElement>(null);
  const [now, setNow] = useState(0);
  const language = i18n.language === 'en' ? 'en' : 'ko';
  const title = useTitle(video.id);
  const captions = (phone ? video.captionsNarrow : undefined) ?? video.captions;
  const languages = Object.keys(captions).sort((a, b) => (a === language ? -1 : b === language ? 1 : 0));
  const scenes = video.scenes ?? [];
  const current = [...scenes].reverse().find((scene) => scene.start <= now)?.key ?? null;
  const sceneText = (key: string) => {
    const own = `ux.tour.scene.${video.id}.${key.split('.').pop() ?? key}`;
    return i18n.exists(own) ? t(own) : '';
  };
  return (
    <Card title={title} sub={t('ux.tour.screens', { screens: video.screens })}>
      <div className={styles.stack}>
        <video
          ref={ref}
          className={styles.video}
          src={`/guides/${video.file}`}
          controls
          preload="metadata"
          playsInline
          aria-label={t('ux.tour.player', { title })}
          onTimeUpdate={(event) => setNow(event.currentTarget.currentTime)}
          onEnded={() => markWatched(video.id)}
        >
          {languages.map((code) => (
            <track
              key={code}
              kind="captions"
              src={`/guides/${captions[code] ?? ''}`}
              srcLang={code}
              label={i18n.exists(`ux.tour.track.${code}`) ? t(`ux.tour.track.${code}`) : code}
              default={code === language}
            />
          ))}
        </video>
        {scenes.length > 0 ? (
          <section className={styles.scenes} aria-labelledby={`tour-scenes-${video.id}`}>
            <h3 id={`tour-scenes-${video.id}`} className={styles.scenesTitle}>
              {t('ux.tour.scenes')}
            </h3>
            <ol className={styles.sceneList}>
              {scenes.map((scene) => {
                const text = sceneText(scene.key);
                return (
                  <li key={scene.key}>
                    <button
                      type="button"
                      className={styles.scene}
                      aria-current={current === scene.key ? 'true' : undefined}
                      aria-label={t('ux.tour.sceneAt', { time: clock(scene.start), text })}
                      onClick={() => {
                        if (ref.current) {
                          ref.current.currentTime = scene.start;
                        }
                        setNow(scene.start);
                      }}
                    >
                      <span className={styles.sceneTime}>{clock(scene.start)}</span>
                      <span>{text}</span>
                    </button>
                  </li>
                );
              })}
            </ol>
          </section>
        ) : null}
      </div>
    </Card>
  );
}
