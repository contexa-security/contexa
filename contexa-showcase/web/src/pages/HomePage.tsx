import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router-dom';
import { usePairs, usePrediction, useVisitor } from '../api/queries';
import type { Choice } from '../api/types';
import { AppHeader } from '../components/AppHeader';
import { StateScreen } from '../components/StateScreen';
import styles from './HomePage.module.css';

/**
 * First screen (deck p.9): one question, two equal buttons that are also the visitor's prediction, and a way to skip.
 * The question is the first recorded pair's attack; the vote is stored once per visitor and scene.
 */
export default function HomePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const navigate = useNavigate();
  const pairs = usePairs();
  const visitor = useVisitor();
  const prediction = usePrediction();

  const pair = pairs.data
    ?.filter((candidate) => candidate.recorded)
    .sort((left, right) => left.order - right.order)[0];
  const scene = pair ? `${pair.key}:ATTACK` : null;

  async function vote(choice: Choice) {
    if (!pair || !scene) {
      return;
    }
    let stored: Choice = choice;
    try {
      const result = await prediction.mutateAsync({ scene, choice });
      stored = result?.choice ?? choice;
    } catch {
      // A vote that could not be stored does not stop the replay; it is simply not counted.
    }
    void navigate(`/replay/${pair.key}`, { state: { choice: stored } });
  }

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" className={styles.page}>
        {pairs.isPending ? <StateScreen kind="loading" /> : null}
        {pairs.isError ? <StateScreen kind="error" onRetry={() => void pairs.refetch()} /> : null}
        {pairs.isSuccess && !pair ? <StateScreen kind="notReady" /> : null}
        {pair ? (
          <section className={styles.entry} aria-labelledby="entry-question">
            <p className={styles.eyebrow}>{t('entry.eyebrow')}</p>
            <h1 id="entry-question" className={styles.question}>
              {pair.question[language]}
            </h1>
            <p className={styles.prompt}>{t('entry.prompt')}</p>
            <div className={styles.votes}>
              {(['ALLOW', 'BLOCK'] as const).map((choice) => (
                <button
                  key={choice}
                  type="button"
                  className={styles.vote}
                  disabled={prediction.isPending || visitor.isPending}
                  aria-pressed={visitor.data?.predictions[scene ?? ''] === choice}
                  onClick={() => void vote(choice)}
                >
                  {t(choice === 'ALLOW' ? 'entry.vote.allow' : 'entry.vote.block')}
                </button>
              ))}
            </div>
            <Link className={styles.skip} to={`/replay/${pair.key}`}>
              {t('entry.skip')} <span aria-hidden="true">›</span>
            </Link>
            <p className={styles.footer}>{t('entry.footer')}</p>
          </section>
        ) : null}
      </main>
    </>
  );
}
