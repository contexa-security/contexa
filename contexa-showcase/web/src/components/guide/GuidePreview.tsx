import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useGuides } from '../../api/guides';
import { Modal } from '../common/Modal';
import styles from './GuidePreview.module.css';
import scripts from './guides.json';

export type GuideId = keyof typeof scripts;

/**
 * The preview at a feature's entrance (가이드영상-계획.md 4절): a quiet button naming the video's length, and a window
 * with the video, its caption tracks (the screen language's on by default) and the same lines as a transcript, for a
 * visitor watching without sound or with a screen reader. Nothing plays until the visitor presses Play; the window
 * closes like every modal. A guide that was not recorded yet draws nothing.
 */
export function GuidePreview({ id }: { readonly id: GuideId }) {
  const { t, i18n } = useTranslation();
  const guides = useGuides();
  const [open, setOpen] = useState(false);
  const video = guides.data?.[id];
  if (!video) {
    return null;
  }
  const script = scripts[id];
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const length = Math.round(video.durationSec);
  const minutes = Math.floor(length / 60);
  const seconds = length % 60;
  return (
    <>
      <button type="button" className={styles.button} aria-haspopup="dialog" onClick={() => setOpen(true)}>
        <span className={styles.play} aria-hidden="true" />
        {t('guide.preview', { minutes, seconds })}
      </button>
      <Modal open={open} onClose={() => setOpen(false)} title={t(script.title)} wide>
        <video className={styles.video} src={`/guides/${video.file}`} controls preload="metadata">
          {Object.entries(video.captions).map(([lang, file]) => (
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
        <h3 className={styles.heading}>{t('guide.transcript')}</h3>
        <ol className={styles.lines}>
          {script.scenes.map((key) => (
            <li key={key}>{t(key)}</li>
          ))}
        </ol>
        <p className={styles.recorded}>
          {t('guide.recorded', { date: video.recordedAt.slice(0, 10), screens: video.screens })}
        </p>
      </Modal>
    </>
  );
}
