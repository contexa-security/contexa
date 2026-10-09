import { useQuery } from '@tanstack/react-query';
import { useId, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { getJson } from '../../api/http';
import { downloadRunRecord } from '../../api/runRecord';
import type { RunScore } from '../../api/types';
import { Icon } from '../Icon';
import { utcTime } from '../../journey/format';
import styles from './SourceMark.module.css';

/** The only four sources of a value on screen (source slide). */
export type SourceKind = 'ENGINE' | 'BUSINESS' | 'CASE' | 'MEASUREMENT';

interface SourceMarkProps {
  readonly kind: SourceKind;
  readonly runId?: string | null;
  readonly step?: number | null;
  /** When the record was written, as an ISO instant; shown in UTC. */
  readonly recordedAt?: string | null;
  /** One line of the original record the value was read from. */
  readonly original?: string | null;
  /** A measured value (teasers, benchmark) rather than the visitor's own run (plan 1절 7). */
  readonly measured?: boolean;
  /** The original text passed its retention period; the summary values remain. */
  readonly retired?: boolean;
  readonly originalHref?: string | null;
  /** The step whose stored records can be downloaded as one file, with the file's SHA-256 shown after it. */
  readonly record?: { readonly runId: string; readonly step: number } | null;
  /** Anything more the place of use states about the source, such as a formula. */
  readonly children?: ReactNode;
}

/**
 * The tag next to every number and sentence (source slide): clicking it opens, in place, where the value came from,
 * the run and request, when it was recorded, and one line of the original.
 */
export function SourceMark({
  kind,
  runId = null,
  step = null,
  recordedAt = null,
  original = null,
  measured = false,
  retired = false,
  originalHref = null,
  record = null,
  children,
}: SourceMarkProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [download, setDownload] = useState<{ readonly hash: string | null; readonly failed: boolean } | null>(
    null,
  );
  const boxId = useId();
  // A run's recorded time (plan 1절 4): the engine's decision of the step, or the run's end for the whole run, read when
  // the box opens so a run still going shows its time once recorded.
  const score = useQuery({
    queryKey: ['run-score', runId, 'source'],
    queryFn: () => getJson<RunScore>(`/api/runs/${encodeURIComponent(runId ?? '')}/score`),
    enabled: open && runId !== null && recordedAt === null,
    staleTime: 0,
    retry: 1,
  }).data;
  const runTime =
    recordedAt ??
    (step === null
      ? (score?.finishedAt ?? null)
      : (score?.verdicts?.find((verdict) => verdict.score.stepNo === step)?.decidedAt ?? null));
  const downloadRecord = async (target: { readonly runId: string; readonly step: number }) => {
    try {
      setDownload({ hash: await downloadRunRecord(target.runId, target.step), failed: false });
    } catch {
      setDownload({ hash: null, failed: true });
    }
  };
  return (
    <span className={styles.mark}>
      <button
        type="button"
        className={styles.button}
        aria-expanded={open}
        aria-controls={boxId}
        onClick={() => setOpen((value) => !value)}
      >
        <Icon name="info" />
        {measured ? t('source.measured') : t('source.button')}
      </button>
      {open ? (
        <span id={boxId} role="group" aria-label={t('source.title')} className={styles.box}>
          <span className={styles.line}>{t(`source.kind.${kind}`)}</span>
          {runId ? (
            <span className={styles.line}>
              {step === null ? t('source.runOnly', { runId }) : t('source.run', { runId, step })}
            </span>
          ) : null}
          {runTime ? (
            <span className={styles.line}>{t('source.recordedAt', { time: utcTime(runTime) })}</span>
          ) : null}
          {retired ? (
            <span className={styles.line}>{t('source.retired')}</span>
          ) : original ? (
            <span className={styles.original}>
              <span className={styles.originalLabel}>{t('source.original')}</span> {original}
            </span>
          ) : null}
          {children ? <span className={styles.line}>{children}</span> : null}
          {originalHref || record ? (
            <span className={styles.links}>
              {originalHref && !retired ? <a href={originalHref}>{t('source.viewOriginal')}</a> : null}
              {record ? (
                <button type="button" className={styles.download} onClick={() => void downloadRecord(record)}>
                  {t('source.download')}
                </button>
              ) : null}
            </span>
          ) : null}
          {download?.hash ? (
            <span className={styles.hash}>{t('source.hash', { hash: download.hash })}</span>
          ) : null}
          {download?.failed ? (
            <span className={styles.line} role="alert">
              {t('source.downloadFailed')}
            </span>
          ) : null}
          <button type="button" className={styles.closeBox} onClick={() => setOpen(false)}>
            {t('source.close')}
          </button>
        </span>
      ) : null}
    </span>
  );
}
