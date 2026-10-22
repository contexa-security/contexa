import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useDetail, type DetailTab } from '../detail/useDetail';
import { Icon } from '../Icon';
import styles from './FrameParts.module.css';

interface RoleCardProps {
  /** Who the visitor is on this part, in a few words. */
  readonly role: ReactNode;
  /** Up to three short lines of the situation. */
  readonly lines: readonly ReactNode[];
}

/** The visitor's role on a part's cover (T1): who you are now and the situation in three lines at most. */
export function RoleCard({ role, lines }: RoleCardProps) {
  return (
    <section className={styles.role}>
      <p className={styles.roleName}>{role}</p>
      <ul className={styles.roleLines}>
        {lines.slice(0, 3).map((line, index) => (
          <li key={index}>{line}</li>
        ))}
      </ul>
    </section>
  );
}

interface SourceLineProps {
  /**
   * Where the numbers come from: the visitor's own run, the same situation sent several times, the latest real request
   * in the same situation (the cover and the comparison before sending), one earlier real request in the same
   * situation, one under a different setting than now, or the tally of the judgments Contexa made in this demo with
   * the hold times set in Contexa (2-6), or what Contexa learned from the requests sent beforehand (3-0, 3-1).
   */
  readonly kind: 'run' | 'measured' | 'latest' | 'earlier' | 'older' | 'tally' | 'learned';
  /** The run the numbers belong to, opened by "see the record" in the decision details; none, no button. */
  readonly runId?: string | null;
  readonly step?: number;
}

/** The screen's one source line (R-10): where the numbers come from, and the record behind them on demand. */
export function SourceLine({ kind, runId = null, step = 1 }: SourceLineProps) {
  const { t } = useTranslation();
  const detail = useDetail();
  return (
    <>
      <span>{t(`frame.source.${kind}`)}</span>
      {runId ? (
        <button type="button" className={styles.sourceOpen} onClick={() => detail.show(runId, step)}>
          {t('frame.source.open')}
        </button>
      ) : null}
    </>
  );
}

interface DetailChipProps {
  readonly runId: string;
  readonly step?: number;
  readonly tab?: DetailTab;
}

/** The one "see details" chip of a result or reason screen (R-2): it opens the decision details window. */
export function DetailChip({ runId, step = 1, tab = 'summary' }: DetailChipProps) {
  const { t } = useTranslation();
  const detail = useDetail();
  return (
    <button type="button" className={styles.detail} onClick={() => detail.show(runId, step, tab)}>
      <Icon name="search" className={styles.detailIcon} />
      {t('frame.detail')}
    </button>
  );
}
