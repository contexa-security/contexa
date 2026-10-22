import { useTranslation } from 'react-i18next';
import { useDetail } from '../detail/useDetail';
import styles from './SourceBadge.module.css';

/**
 * Where a value comes from, in one of three badges (최종화면-구현계획 F0-6, 설계서 출처 배지 3종): the visitor's own run
 * just now, the record of the same situation run several times, or a record under another setting than now. A badge
 * with a run opens its decision details ("판단 근거 보기").
 */
export type SourceKind = 'run' | 'repeated' | 'other';

interface SourceBadgeProps {
  readonly kind: SourceKind;
  /** The run the value belongs to; the badge then names it and opens its record. */
  readonly runId?: string | null;
  readonly step?: number;
  /** How many runs the record holds, for the repeated record. */
  readonly runs?: number | null;
  /** What the badge says in place of its kind's words (a measured line: "같은 상황 5회 실행: 5회 모두 차단"). */
  readonly label?: string;
}

export function SourceBadge({ kind, runId = null, step = 1, runs = null, label }: SourceBadgeProps) {
  const { t } = useTranslation();
  const detail = useDetail();
  const words = label ?? t(`badge.${kind}`, { runs: runs ?? 0 });
  if (runId) {
    return (
      <button
        type="button"
        className={styles.badge}
        data-kind={kind}
        onClick={() => detail.show(runId, step)}
      >
        <span>{words}</span>
        <span className={styles.run}>{runId}</span>
      </button>
    );
  }
  return (
    <span className={styles.badge} data-kind={kind}>
      <span className={styles.words}>{words}</span>
    </span>
  );
}
