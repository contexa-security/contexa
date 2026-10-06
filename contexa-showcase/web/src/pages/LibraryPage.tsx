import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { usePairs, useReplay } from '../api/queries';
import { AppHeader } from '../components/AppHeader';
import { StateScreen } from '../components/StateScreen';
import { LIBRARY, type LibraryEntry } from '../content/library';
import { OUTCOME_KEYS } from '../domain/verdict';
import styles from './LibraryPage.module.css';

/** Outcomes where the data did not leave; an unresolved request is not counted as stopped. */
const STOPPING: ReadonlySet<string> = new Set(['STOPPED', 'HELD', 'CUT']);

/**
 * Scenario library (deck p.14): every attack group with its look-alike legitimate request and standard mapping. A
 * published pair shows the five approaches' recorded results and opens its replay; the rest are being prepared.
 */
export default function LibraryPage() {
  const { t } = useTranslation();
  const pairs = usePairs();
  const recorded = new Set(pairs.data?.filter((pair) => pair.recorded).map((pair) => pair.key) ?? []);

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" className={styles.page}>
        <header className={styles.header}>
          <h1 className={styles.title}>{t('library.title')}</h1>
          <p className={styles.lead}>{t('library.lead')}</p>
        </header>
        {pairs.isPending ? <StateScreen kind="loading" /> : null}
        {pairs.isError ? <StateScreen kind="error" onRetry={() => void pairs.refetch()} /> : null}
        {pairs.isSuccess ? (
          <ul className={styles.cards}>
            {/* Scenes with a real record come first; the ones in preparation follow in catalogue order. */}
            {[...LIBRARY]
              .sort((left, right) => Number(recorded.has(right.key)) - Number(recorded.has(left.key)))
              .map((entry) => (
              <li key={entry.key}>
                <LibraryCard entry={entry} recorded={recorded.has(entry.key)} />
              </li>
            ))}
          </ul>
        ) : null}
        {pairs.isSuccess ? (
          <section className={styles.industries} aria-labelledby="library-industry">
            <h2 id="library-industry" className={styles.sectionTitle}>
              {t('library.industry.title')}
            </h2>
            <ul className={styles.industryList}>
              <li data-current="true">{t('library.industry.manufacturing')}</li>
              <li>{t('library.industry.saas')}</li>
              <li>{t('library.industry.finance')}</li>
            </ul>
          </section>
        ) : null}
      </main>
    </>
  );
}

function LibraryCard({ entry, recorded }: { readonly entry: LibraryEntry; readonly recorded: boolean }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  return (
    <article
      className={styles.card}
      data-featured={entry.featured === true}
      aria-labelledby={`card-${entry.key}`}
    >
      <p className={styles.meta}>
        <span className={styles.code}>{entry.key}</span>
        <span className={styles.standard}>{entry.standard}</span>
      </p>
      <h2 id={`card-${entry.key}`} className={styles.cardTitle}>
        {entry.attack[language]}
      </h2>
      <p className={styles.twin}>
        {entry.comparison ? entry.twin[language] : t('library.twin', { twin: entry.twin[language] })}
      </p>
      {recorded ? (
        <RecordedPair pairKey={entry.key} />
      ) : (
        <p className={styles.preparing}>{t('library.preparing')}</p>
      )}
    </article>
  );
}

function RecordedPair({ pairKey }: { readonly pairKey: string }) {
  const { t } = useTranslation();
  const replay = useReplay(pairKey);
  return (
    <div className={styles.recorded}>
      <ul className={styles.scenes}>
        {replay.data?.scenes.map((scene) => {
          const contexa = scene.layers.find((layer) => layer.control === 'D');
          const stopped = scene.layers.filter((layer) => STOPPING.has(layer.outcome)).length;
          return (
            <li key={scene.kind} className={styles.scene}>
              <span className={styles.sceneLabel}>{t(`replay.scene.${scene.kind}`)}</span>
              <span>{t('library.stopped', { stopped, total: scene.layers.length })}</span>
              {contexa ? (
                <span className={styles.contexa}>
                  {t('library.contexa', { outcome: t(OUTCOME_KEYS[contexa.outcome]) })}
                </span>
              ) : null}
            </li>
          );
        })}
      </ul>
      <Link className={styles.play} to={`/replay/${pairKey}`}>
        {t('library.play')} <span aria-hidden="true">›</span>
      </Link>
    </div>
  );
}
