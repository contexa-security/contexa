import { useTranslation } from 'react-i18next';
import { useAnatomy } from '../../api/anatomy';
import { useLatestRelease, type StoredRelease } from '../../api/follow';
import { Chip } from '../../components/main/Chip';
import { SourceBadge } from '../../components/main/SourceBadge';
import { count, utcTime } from '../../journey/format';
import styles from './ReleaseRecord.module.css';

/** The release's steps in order, each with the stored time it happened. */
const STAGES = [
  { id: 'blocked', at: 'blocked_at' },
  { id: 'code', at: 'code_requested_at' },
  { id: 'verified', at: 'verified_at' },
  { id: 'requested', at: 'requested_at' },
  { id: 'approved', at: 'approved_at' },
  { id: 'resent', at: 'reissue_sent_at' },
] as const;

/**
 * The latest block of the demo that was actually released (최종화면-구현계획 FU-5): each step with the time the portal
 * recorded it, the engine's own record of the block as its administrator API returned it, the original request sent
 * again after the approval, and what the run learned. A block forced for checking the flow is named as such; the
 * release after it is the engine's own handling either way.
 */
export function ReleaseRecord() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const latest = useLatestRelease();
  const record = latest.data ?? null;
  const anatomy = useAnatomy(record?.runId ?? null, record?.stepNo ?? 1);
  const release = (anatomy.data?.recovery?.release ?? null) as StoredRelease | null;

  if (latest.isPending || (record !== null && anatomy.isPending)) {
    return null;
  }
  if (record === null || release === null) {
    return <p className={styles.none}>{t('follow.release.none')}</p>;
  }
  const block = release.block_record;
  const learning = anatomy.data?.learning ?? null;
  const before = learning?.template?.['baselineUpdateCount'];
  const after = learning?.atRunEnd?.['baselineUpdateCount'];
  // The first line of each record the engine stored after the release, as it wrote it.
  const learned = (learning?.newBehaviourDocuments ?? []).map(
    (record) => (record.content ?? '').split(/\r?\n/)[0] ?? '',
  );
  return (
    <section className={styles.record} aria-labelledby="release-record-title">
      <h2 id="release-record-title" className={styles.title}>
        {t('follow.release.title')}
      </h2>
      {record.forcedAction ? (
        <p className={styles.forced}>
          <Chip kind="wait">{t('follow.release.forced')}</Chip>
          <span>{t('follow.release.forcedNote')}</span>
        </p>
      ) : null}
      <ol className={styles.stages}>
        {STAGES.map((stage, index) => {
          const at = release[stage.at];
          return (
            <li key={stage.id} className={styles.stage} data-done={at ? true : undefined}>
              <span className={styles.stageNo}>{index + 1}</span>
              <b className={styles.stageName}>{t(`follow.release.stage.${stage.id}`)}</b>
              <span className={styles.stageAt}>{at ? utcTime(at).slice(11) : '—'}</span>
            </li>
          );
        })}
      </ol>
      <p className={styles.utc}>
        {t('follow.release.utc', { date: release.blocked_at?.slice(0, 10) ?? '—' })}
      </p>
      <dl className={styles.facts}>
        <div>
          <dt>{t('follow.release.engineReason')}</dt>
          {/* A forced block's reason is a setting's name: said in plain words, the original folded (V-49). */}
          {record.forcedAction ? (
            <dd>
              <span>{t('follow.release.forcedReason')}</span>
              <details className={styles.raw}>
                <summary>{t('follow.release.raw')}</summary>
                <span lang="en">{block?.reasoning ?? '—'}</span>
              </details>
            </dd>
          ) : (
            <dd>
              <span lang="en">{block?.reasoning ?? '—'}</span>
            </dd>
          )}
        </div>
        <div>
          <dt>{t('follow.release.mfa')}</dt>
          <dd>{block?.mfaVerified ? t('show.release.adminMfaDone') : t('show.release.adminMfaNone')}</dd>
        </div>
        <div>
          <dt>{t('follow.release.reason')}</dt>
          <dd>{block?.unblockReason ?? '—'}</dd>
        </div>
        <div>
          <dt>{t('follow.release.resent')}</dt>
          <dd>
            {release.reissue_status === null ? (
              '—'
            ) : (
              // The row's name says what it is; the chip holds only the count and the status (B-16).
              <Chip kind={release.reissue_status === 200 ? 'allow' : 'bad'}>
                {t('follow.release.resentValue', {
                  count: release.reissue_delivered ?? 0,
                  items: count(release.reissue_delivered ?? 0, language),
                  status: release.reissue_status,
                })}
              </Chip>
            )}
          </dd>
        </div>
      </dl>
      <div className={styles.learning}>
        <h3 className={styles.learningTitle}>{t('main.proof.learn.title')}</h3>
        <p className={styles.learnCounts}>
          {t('follow.release.learnCounts', {
            before: before === undefined ? '…' : count(before, language),
            after: after === undefined ? '…' : count(after, language),
          })}
        </p>
        {/*
          A forced block kept no facts of the original request, so the release learns the block alone, not the
          request (V-14, BlockedUserService.syncAdminOverride).
        */}
        {record.forcedAction ? <p className={styles.why}>{t('follow.release.learnForced')}</p> : null}
        {learned.length > 0 ? (
          <ul className={styles.learned} aria-label={t('follow.release.learned')}>
            {learned.map((line, index) => (
              <li key={index}>
                <span className={styles.learnedLabel}>{t('follow.release.learned')}</span>
                <code lang="en">{line}</code>
              </li>
            ))}
          </ul>
        ) : (
          <p className={styles.utc}>{t('follow.release.learnedNone')}</p>
        )}
      </div>
      <div className={styles.badges}>
        <SourceBadge kind="run" label={t('follow.release.run')} runId={record.runId} step={record.stepNo} />
      </div>
    </section>
  );
}
