import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import type { StreamProgress } from '../api/types';
import type { Verdict } from '../domain/verdict';
import type { TimelineEntry } from './AnalysisTimeline';
import { AnalysisTimeline } from './AnalysisTimeline';
import { StreamMeter } from './StreamMeter';
import { VerdictChip } from './VerdictChip';
import styles from './EvidenceDrawer.module.css';

export interface EvidenceChain {
  /** Null when no engine decision exists: a 403 from a permission check is not the engine's block (deck p.24). */
  readonly decisionId: string | null;
  readonly verdict: Verdict;
  /** The engine gave no decision (technical failure), so the verdict chip says "unresolved". */
  readonly unresolved?: boolean;
  readonly timing: string;
  readonly httpStatus: number | null;
  readonly outcome: string;
  /** Raw engine reasoning; shown untranslated with an "engine original" label. */
  readonly engineReasoning?: string;
  /** Engine events on one time axis with the response (deck p.11); absent when the engine did not analyse. */
  readonly timeline?: {
    readonly entries: readonly TimelineEntry[];
    readonly summary: string | null;
  };
  /** How far a streamed export got, exposure included (deck p.11). */
  readonly stream?: StreamProgress;
}

interface EvidenceDrawerProps {
  readonly title: string;
  readonly evidence: EvidenceChain | null;
  readonly onClose: () => void;
}

/**
 * Modal drawer built on the native dialog element, which provides the focus trap, Escape handling
 * and focus return that keyboard users need.
 */
export function EvidenceDrawer({ title, evidence, onClose }: EvidenceDrawerProps) {
  const { t } = useTranslation();
  const dialogRef = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) {
      return;
    }
    if (evidence && !dialog.open) {
      dialog.showModal();
    } else if (!evidence && dialog.open) {
      dialog.close();
    }
  }, [evidence]);

  return (
    <dialog ref={dialogRef} className={styles.drawer} aria-labelledby="evidence-title" onClose={onClose}>
      {evidence ? (
        <div className={styles.body}>
          <header className={styles.header}>
            <h2 id="evidence-title" className={styles.title}>
              {t('evidence.title')} · {title}
            </h2>
            <button type="button" className={styles.close} onClick={onClose}>
              {t('evidence.close')}
            </button>
          </header>
          <p className={styles.summary}>{t('evidence.summary')}</p>
          <dl className={styles.chain}>
            <div className={styles.link}>
              <dt>{t('evidence.decision')}</dt>
              <dd>
                <VerdictChip verdict={evidence.verdict} showCode unresolved={evidence.unresolved ?? false} />
              </dd>
            </div>
            <div className={styles.link}>
              <dt>{t('evidence.timing')}</dt>
              <dd>{evidence.timing}</dd>
            </div>
            <div className={styles.link}>
              <dt>{t('evidence.http')}</dt>
              <dd className={styles.mono}>{evidence.httpStatus ?? '—'}</dd>
            </div>
            <div className={styles.link} data-primary="true">
              <dt>
                {t('evidence.outcome')} <span className={styles.primary}>{t('evidence.primary')}</span>
              </dt>
              <dd>{evidence.outcome}</dd>
            </div>
          </dl>
          <p className={styles.decisionId}>
            {t('evidence.decisionId')}{' '}
            <span className={styles.mono}>{evidence.decisionId ?? t('evidence.noDecision')}</span>
          </p>
          {evidence.stream ? <StreamMeter stream={evidence.stream} /> : null}
          {evidence.timeline ? (
            <AnalysisTimeline entries={evidence.timeline.entries} summary={evidence.timeline.summary} />
          ) : null}
          {evidence.engineReasoning ? (
            <section className={styles.reasoning} aria-label={t('reason.engineOriginal')}>
              <h3 className={styles.reasoningTitle}>{t('reason.engineOriginal')}</h3>
              <p lang="en">{evidence.engineReasoning}</p>
            </section>
          ) : null}
        </div>
      ) : null}
    </dialog>
  );
}
