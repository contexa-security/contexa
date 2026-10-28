import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useGuides, videoOf } from '../../api/guides';
import type { GuideId } from './guideConfig';
import { GuideWindow } from './GuideWindow';
import { useWatched } from './guideWatched';
import styles from './GuidePreview.module.css';

export type { GuideId } from './guideConfig';

/**
 * The link to a guide video and its window (가이드영상-제작기획안.md 4·6절): a filled pill naming the video's length that
 * turns into "watch again" once the video was watched to the end in this browser, and a window with the video, its
 * captions on a band under it, the scene lines and the recording's date. Nothing plays until the visitor presses Play;
 * the window closes like every modal. A guide that was not recorded yet draws nothing.
 */
export function GuidePreview({ id, variant = 'head' }: { readonly id: GuideId; readonly variant?: 'head' | 'start' }) {
  const { t, i18n } = useTranslation();
  const guides = useGuides();
  const watched = useWatched(id);
  const [open, setOpen] = useState(false);
  const video = videoOf(guides.data, id, i18n.language === 'ko' ? 'ko' : 'en');
  if (!video) {
    return null;
  }
  const length = Math.round(video.durationSec);
  const minutes = Math.floor(length / 60);
  const seconds = length % 60;
  return (
    <div className={styles.slot} data-guide-slot data-variant={variant}>
      <button
        type="button"
        className={styles.link}
        data-guide-link
        aria-haspopup="dialog"
        onClick={() => setOpen(true)}
      >
        <span className={styles.mark} data-watched={watched ? '' : undefined} aria-hidden="true" />
        {t(watched ? 'guide.previewAgain' : 'guide.preview', { minutes, seconds })}
      </button>
      <GuideWindow id={id} video={video} open={open} onClose={() => setOpen(false)} />
    </div>
  );
}
