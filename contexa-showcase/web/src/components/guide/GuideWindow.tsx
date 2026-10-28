import { useTranslation } from 'react-i18next';
import type { GuideVideo } from '../../api/guides';
import { Modal } from '../common/Modal';
import { guideEntry, type GuideId } from './guideConfig';
import { GuidePlayer } from './GuidePlayer';
import { markWatched } from './guideWatched';
import styles from './GuidePlayer.module.css';

/**
 * The window of one guide video (가이드영상-제작기획안.md 4·6절): the video with its caption band, the scene lines and the
 * recording's date. The link of a screen and the list of every video open the same one; watching to the end marks it
 * watched in this browser.
 */
export function GuideWindow({
  id,
  video,
  open,
  onClose,
}: {
  readonly id: GuideId;
  readonly video: GuideVideo;
  readonly open: boolean;
  readonly onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  return (
    <Modal open={open} onClose={onClose} title={t(guideEntry(id).title)} wide>
      <GuidePlayer id={id} video={video} language={language} onEnded={() => markWatched(id)} />
      <p className={styles.recorded}>
        {t('guide.recorded', { date: video.recordedAt.slice(0, 10), screens: video.screens })}
      </p>
    </Modal>
  );
}
