import { useTranslation } from 'react-i18next';
import styles from './AnalysisTimeline.module.css';

export interface TimelineEntry {
  readonly key: string;
  readonly kind: 'engine' | 'response';
  readonly label: string;
  /** Milliseconds from sending the request; the value shown is exactly this number. */
  readonly atMs: number;
  readonly note: string | null;
}

interface AnalysisTimelineProps {
  readonly entries: readonly TimelineEntry[];
  /** One sentence on when the decision took effect relative to the response. */
  readonly summary: string | null;
}

const NUMBER = new Intl.NumberFormat('en-US');

/**
 * The engine's recorded events and the response on one axis that starts when the request was sent. The track is
 * decorative; the ordered list carries the same values for assistive technology.
 */
export function AnalysisTimeline({ entries, summary }: AnalysisTimelineProps) {
  const { t } = useTranslation();
  const span = Math.max(1, ...entries.map((entry) => entry.atMs));

  return (
    <section className={styles.timeline} aria-labelledby="timeline-title">
      <h3 id="timeline-title" className={styles.title}>
        {t('timeline.title')}
      </h3>
      <p className={styles.basis}>{t('timeline.basis')}</p>
      {summary ? <p className={styles.summary}>{summary}</p> : null}
      <div className={styles.track} aria-hidden="true">
        {entries.map((entry) => (
          <span
            key={entry.key}
            className={styles.mark}
            data-kind={entry.kind}
            style={{ insetInlineStart: `${(Math.max(0, entry.atMs) / span) * 100}%` }}
          />
        ))}
      </div>
      <ol className={styles.events}>
        {entries.map((entry) => (
          <li key={entry.key} className={styles.event} data-kind={entry.kind}>
            <span className={styles.offset} data-testid="timeline-offset">
              +{NUMBER.format(entry.atMs)} ms
            </span>
            <span className={styles.label}>
              {entry.label}
              {entry.note ? <span className={styles.note}>{entry.note}</span> : null}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}
