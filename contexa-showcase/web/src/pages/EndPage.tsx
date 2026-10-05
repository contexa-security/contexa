import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router-dom';
import { postJson } from '../api/http';
import { useExperienceResult, useLiveConfig, useVisitor } from '../api/queries';
import type { ExperienceResult, ShareResponse } from '../api/types';
import { AppHeader } from '../components/AppHeader';
import { Icon } from '../components/Icon';
import { StateScreen } from '../components/StateScreen';
import { OUTCOME_KEYS } from '../domain/verdict';
import styles from './EndPage.module.css';

/**
 * End screen (deck p.15): the visitor's result in numbers from the server, the proofs the recording supports, one
 * next action (try other conditions), and small links. The share card carries the result values only.
 */
export default function EndPage() {
  const { t } = useTranslation();
  const { pairKey } = useParams();
  useVisitor();
  const result = useExperienceResult(pairKey);
  // The recovery line links to "try it yourself"; it is shown only where live runs are open, so it never leads to a
  // page that cannot run anything.
  const liveConfig = useLiveConfig();
  const recoveryOpen = liveConfig.isSuccess && liveConfig.data.scenarios.length > 0;

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" className={styles.page}>
        {result.isPending ? <StateScreen kind="loading" /> : null}
        {result.isError ? <StateScreen kind="notReady" /> : null}
        {result.data && pairKey ? (
          <EndBody result={result.data} pairKey={pairKey} recoveryOpen={recoveryOpen} />
        ) : null}
      </main>
    </>
  );
}

interface EndBodyProps {
  readonly result: ExperienceResult;
  readonly pairKey: string;
  readonly recoveryOpen: boolean;
}

function EndBody({ result, pairKey, recoveryOpen }: EndBodyProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [share, setShare] = useState<ShareResponse | null>(null);
  const [shareFailed, setShareFailed] = useState(false);
  const [copied, setCopied] = useState(false);
  const carriedOver = result.scenes.some((scene) => scene.carriedOver);
  const contexaAll = result.contexa.hits === result.contexa.total;

  async function createShare() {
    setShareFailed(false);
    const response = await postJson<ShareResponse>('/api/shares', { pairKey, language });
    if (response.status === 201 && response.body) {
      setShare(response.body);
    } else {
      setShareFailed(true);
    }
  }

  async function copy(url: string) {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <>
      <section className={styles.result} aria-labelledby="end-title">
        <p className={styles.eyebrow}>{t('end.eyebrow', { count: result.scenes.length })}</p>
        <h1 id="end-title" className={styles.title}>
          {t('end.title')}
        </h1>
        <dl className={styles.scores}>
          <div className={styles.score}>
            <dt>{t('end.mine')}</dt>
            <dd className={styles.scoreValue}>
              {result.mine ? `${result.mine.hits}/${result.mine.total}` : t('end.noVote')}
            </dd>
          </div>
          <div className={styles.score} data-contexa="true">
            <dt>Contexa</dt>
            <dd className={styles.scoreValue}>{`${result.contexa.hits}/${result.contexa.total}`}</dd>
          </div>
        </dl>
        {carriedOver ? <p className={styles.note}>{t('end.carriedOver')}</p> : null}
        <ul className={styles.scenes}>
          {result.scenes.map((scene) => (
            <li key={scene.kind} className={styles.scene}>
              <span className={styles.sceneKind}>{t(`replay.scene.${scene.kind}`)}</span>
              <span className={styles.call}>
                {scene.choice
                  ? t('end.scene.call', { choice: t(`replay.choice.${scene.choice}`) })
                  : t('end.scene.noCall')}
                {scene.myCorrect === null ? null : <Mark right={scene.myCorrect} />}
              </span>
              <span className={styles.call}>
                {t('end.scene.contexa', { outcome: t(OUTCOME_KEYS[scene.contexaOutcome]) })}
                <Mark right={scene.contexaCorrect} />
              </span>
            </li>
          ))}
        </ul>
      </section>

      <ul className={styles.proofs}>
        <li className={styles.proof}>
          {contexaAll ? <Icon name="check" className={styles.proofIcon} /> : null}
          <span>
            {contexaAll
              ? t('end.proof.precise')
              : t('end.proof.score', { hits: result.contexa.hits, total: result.contexa.total })}
          </span>
        </li>
        {recoveryOpen ? (
          <li className={styles.proof}>
            <span>{t('end.proof.recover')}</span>
            <Link className={styles.proofLink} to="/try">
              {t('end.proof.recoverLink')}
            </Link>
          </li>
        ) : null}
        <li className={styles.proof}>
          <span>{t('end.proof.adopt')}</span>
          <Link className={styles.proofLink} to="/adopt">
            {t('end.proof.adoptLink')}
          </Link>
        </li>
      </ul>

      <Link className={styles.primary} to="/explore">
        {t('end.primary')} <span aria-hidden="true">›</span>
      </Link>

      <nav className={styles.links} aria-label={t('end.more')}>
        <button type="button" className={styles.linkButton} onClick={() => void createShare()}>
          {t('end.share')}
        </button>
        <Link className={styles.link} to="/stats">
          {t('end.stats')}
        </Link>
        <Link className={styles.link} to={`/replay/${pairKey}`}>
          {t('end.replay')}
        </Link>
      </nav>

      {shareFailed ? (
        <p className={styles.error} role="alert">
          {t('end.shareCard.error')}
        </p>
      ) : null}
      {share ? (
        <section className={styles.share} aria-labelledby="share-title">
          <h2 id="share-title" className={styles.shareTitle}>
            {t('end.shareCard.title')}
          </h2>
          <img
            className={styles.card}
            src={share.image}
            width={1200}
            height={630}
            alt={t('end.shareCard.alt', {
              score: `${result.mine ? `${t('end.mine')} ${result.mine.hits}/${result.mine.total} · ` : ''}Contexa ${result.contexa.hits}/${result.contexa.total}`,
            })}
          />
          <p className={styles.note}>{t('end.shareCard.note')}</p>
          <div className={styles.shareRow}>
            <label className={styles.shareLabel} htmlFor="share-url">
              {t('end.shareCard.link')}
            </label>
            <input id="share-url" className={styles.shareUrl} readOnly value={share.url} />
            <button type="button" className={styles.linkButton} onClick={() => void copy(share.url)}>
              {t('end.shareCard.copy')}
            </button>
          </div>
          <p className={styles.status} role="status">
            {copied ? t('end.shareCard.copied') : ''}
          </p>
        </section>
      ) : null}
    </>
  );
}

/** Right or wrong, as an icon and a word together so it never depends on color. */
function Mark({ right }: { readonly right: boolean }) {
  const { t } = useTranslation();
  return (
    <span className={styles.mark} data-right={right}>
      <Icon name={right ? 'check' : 'cross'} />
      {right ? t('end.right') : t('end.wrong')}
    </span>
  );
}
