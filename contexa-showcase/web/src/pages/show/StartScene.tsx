import { useTranslation } from 'react-i18next';
import styles from './ShowPage.module.css';

interface StartSceneProps {
  readonly onStart: () => void;
}

/** The first ten seconds (docs/showcase/화면설계서.md): what this is, and one button into the attacker's seat. */
export function StartScene({ onStart }: StartSceneProps) {
  const { t } = useTranslation();
  return (
    <section className={styles.start} aria-labelledby="start-title">
      <p className={styles.eyebrow}>{t('show.start.eyebrow')}</p>
      <h1 id="start-title" className={styles.display} tabIndex={-1}>
        {t('show.start.title')}
      </h1>
      <p className={styles.body}>{t('show.start.body')}</p>
      <p className={styles.what}>{t('show.start.what')}</p>
      <div className={styles.cta}>
        <button type="button" className={styles.primary} onClick={onStart}>
          {t('show.start.cta')}
        </button>
        <p className={styles.real}>{t('show.start.real')}</p>
      </div>
    </section>
  );
}
