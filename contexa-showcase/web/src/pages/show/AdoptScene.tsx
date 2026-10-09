import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { ADOPT_CODE } from './adoptCode';
import styles from './ShowPage.module.css';

interface AdoptSceneProps {
  readonly onRestart: () => void;
}

/**
 * Scene 5 (docs/showcase/화면설계서.md): the decisions the visitor just saw came from these lines of this demo's own
 * workload, with the annotation the only thing highlighted.
 */
export function AdoptScene({ onRestart }: AdoptSceneProps) {
  const { t } = useTranslation();
  return (
    <section className={styles.adopt} aria-labelledby="adopt-title">
      <h1 id="adopt-title" className={styles.sceneTitle} tabIndex={-1}>
        {t('show.adopt.title')}
      </h1>
      <div className={styles.code}>
        {ADOPT_CODE.map((excerpt) => (
          <figure key={excerpt.path} className={styles.excerpt}>
            {/* Long lines scroll sideways on a phone, so the block takes the keyboard focus too. */}
            <pre className={styles.pre} tabIndex={0} aria-label={excerpt.path.split('/').pop()}>
              <code>
                {excerpt.lines.map((line, index) => (
                  <span key={line} className={index === excerpt.highlight ? styles.lineOn : styles.lineOff}>
                    {line}
                    {'\n'}
                  </span>
                ))}
              </code>
            </pre>
            <figcaption className={styles.source}>
              {t('show.adopt.source', { path: excerpt.path })}
            </figcaption>
          </figure>
        ))}
      </div>
      <p className={styles.body}>{t('show.adopt.lead')}</p>
      <div className={styles.actions}>
        <Link to="/adopt" className={styles.primary}>
          {t('show.adopt.cta')}
        </Link>
        <Link to="/lab" className={styles.secondary}>
          {t('show.adopt.more')}
        </Link>
        <button type="button" className={styles.secondary} onClick={onRestart}>
          {t('show.restart')}
        </button>
      </div>
    </section>
  );
}
