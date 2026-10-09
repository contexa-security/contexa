import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router-dom';
import { postJson } from '../api/http';
import { useLabOptions } from '../api/lab';
import { useExperienceResult, useVisitor } from '../api/queries';
import type { ExperienceResult, ShareResponse } from '../api/types';
import { AppHeader } from '../components/AppHeader';
import { Icon } from '../components/Icon';
import { StateScreen } from '../components/StateScreen';
import { compareConditions } from '../domain/pairs';
import { secondsText } from '../domain/show';
import styles from './EndPage.module.css';

/**
 * End screen (deck p.15): the visitor's result in numbers from the server, the proofs the recording supports, one
 * next action (try other conditions), and small links. The share card carries the result values only.
 */
export default function EndPage() {
  const { pairKey } = useParams();
  useVisitor();
  const result = useExperienceResult(pairKey);

  return (
    <>
      <AppHeader />
      <main id="main" className={styles.page}>
        {result.isPending ? <StateScreen kind="loading" /> : null}
        {result.isError ? <StateScreen kind="notReady" /> : null}
        {result.data && pairKey ? <EndBody result={result.data} pairKey={pairKey} /> : null}
      </main>
    </>
  );
}

interface EndBodyProps {
  readonly result: ExperienceResult;
  readonly pairKey: string;
}

function EndBody({ result, pairKey }: EndBodyProps) {
  const { t, i18n } = useTranslation();
  const options = useLabOptions();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [share, setShare] = useState<ShareResponse | null>(null);
  const [shareFailed, setShareFailed] = useState(false);
  const [copied, setCopied] = useState(false);
  const carriedOver = result.scenes.some((scene) => scene.carriedOver);
  const contexaAll =
    result.contexa.total === result.scenes.length && result.contexa.hits === result.contexa.total;
  // H-09 #28: what the two requests share and where they differ, from the two cases' own definitions.
  const conditionsOf = (key: string | undefined) =>
    options.data?.cases.find((candidate) => candidate.key === key)?.conditions;
  const firstConditions = conditionsOf(result.scenes[0]?.scenarioKey);
  const secondConditions = conditionsOf(result.scenes[1]?.scenarioKey);
  const comparison =
    firstConditions && secondConditions ? compareConditions(firstConditions, secondConditions) : null;
  const fields = (list: readonly string[]) => list.map((field) => t(`lab.field.${field}`)).join(', ');
  const explanation = comparison
    ? [
        comparison.same.length > 0 ? t('end.explainSame', { list: fields(comparison.same) }) : null,
        comparison.different.length > 0
          ? t('end.explainDifferent', { list: fields(comparison.different) })
          : t('end.explainNoDifference'),
        comparison.recordsOnly ? t('end.explainRecordsOnly') : null,
      ]
        .filter((sentence): sentence is string => sentence !== null)
        .join(' ')
    : null;
  // H-09 #29: the recovery is claimed only where a run of this recording went through again after the check.
  const resumed = result.scenes.find((scene) => scene.resumedMillis !== null)?.resumedMillis ?? null;

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
          {/* "Look the same" only where the two cases differ in the company records alone (H-09 #28). */}
          {t(comparison?.recordsOnly ? 'end.titleLookAlike' : 'end.title')}
        </h1>
        {explanation ? <p className={styles.explain}>{explanation}</p> : null}
        <dl className={styles.scores}>
          {/* The visitor's own score exists only for a visitor who voted before the hands-on first screen. */}
          {result.mine ? (
            <div className={styles.score}>
              <dt>{t('end.mine')}</dt>
              <dd className={styles.scoreValue}>{`${result.mine.hits}/${result.mine.total}`}</dd>
            </div>
          ) : null}
          <div className={styles.score} data-contexa="true">
            <dt>{t('end.contexaScore')}</dt>
            <dd className={styles.scoreValue}>{`${result.contexa.hits}/${result.contexa.total}`}</dd>
          </div>
        </dl>
        {carriedOver ? <p className={styles.note}>{t('end.carriedOver')}</p> : null}
        <ul className={styles.scenes}>
          {result.scenes.map((scene) => (
            <li key={scene.kind} className={styles.scene}>
              <span className={styles.sceneKind}>
                {t(`replay.scene.${scene.kind}`)}
                <span className={styles.sceneExpect}>
                  {t('anatomy.truth.classification')}:{' '}
                  {t(`anatomy.class.${scene.truth.classification ?? 'NONE'}`)}
                </span>
              </span>
              <span className={styles.call}>
                {scene.choice
                  ? t('end.scene.call', { choice: t(`replay.choice.${scene.choice}`) })
                  : t('end.scene.noCall')}
                {scene.myCorrect === null ? null : <Mark right={scene.myCorrect} />}
              </span>
              <span className={styles.call}>
                {t('end.scene.contexa', {
                  outcome: t(`score.result.${scene.contexaResult}`, {
                    n: scene.contexaExposed.toLocaleString(),
                    count: scene.contexaExposed,
                  }),
                })}
                {scene.contexaCorrect === null ? null : <Mark right={scene.contexaCorrect} />}
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
        {resumed !== null ? (
          <li className={styles.proof}>
            <span>{t('end.proof.recover', { seconds: secondsText(resumed) })}</span>
          </li>
        ) : null}
        <li className={styles.proof}>
          <span>{t('end.proof.adopt')}</span>
          <Link className={styles.proofLink} to="/adopt">
            {t('end.proof.adoptLink')}
          </Link>
        </li>
      </ul>

      <Link className={styles.primary} to="/">
        {t('end.primary')} <span aria-hidden="true">›</span>
      </Link>

      <nav className={styles.links} aria-label={t('end.more')}>
        <button type="button" className={styles.linkButton} onClick={() => void createShare()}>
          {t('end.share')}
        </button>
        <Link className={styles.link} to="/benchmark">
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
              score: `${result.mine ? `${t('end.shareCard.mine')} ${result.mine.hits}/${result.mine.total} · ` : ''}Contexa ${result.contexa.hits}/${result.contexa.total}`,
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
