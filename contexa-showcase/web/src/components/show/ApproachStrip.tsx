import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import type { RunScore } from '../../api/types';
import { secondsText, type LaneState, type Role } from '../../domain/show';
import type { ControlId } from '../../domain/verdict';
import { CONTROL_ORDER } from '../../domain/verdict';
import styles from './ApproachStrip.module.css';

interface ApproachStripProps {
  readonly role: Role;
  readonly lanes: Readonly<Record<ControlId, LaneState>>;
  readonly total: number;
  /** Heading of the strip; the first request's heading by default. */
  readonly title?: string;
  /** Element ID of the heading, unique on the page. */
  readonly headingId?: string;
  /**
   * Items Contexa handed over once the real owner passed its check and the request went out again; the lane then
   * shows the work done instead of the hold.
   */
  readonly resumedItems?: number | null;
  /** How the work came back: after the identity check or after the release of a block. */
  readonly resumedBy?: 'check' | 'release';
  /** Opens the evidence of an approach once the run's full result is in. */
  readonly onOpenEvidence?: ((control: ControlId) => void) | undefined;
  /**
   * The server's score of the run over the steps sent so far (docs/showcase/데모-재설계.md 5.0); the strip shows its
   * result and right or wrong as they are and judges nothing itself. Without it no mark is shown.
   */
  readonly score?: RunScore | null | undefined;
}

/**
 * The five security approaches that received the same request at the same time (deck p.10). Each shows what happened
 * to the data as it happens, coloured by its consequence for the scene: data leaking or work halted against data
 * protected or work done.
 */
export function ApproachStrip({
  role,
  lanes,
  total,
  title,
  headingId = 'approaches-title',
  resumedItems = null,
  resumedBy = 'check',
  onOpenEvidence,
  score = null,
}: ApproachStripProps) {
  const { t } = useTranslation();
  return (
    <section className={styles.strip} aria-labelledby={headingId}>
      <h2 id={headingId} className={styles.title}>
        {title ?? t('show.lanes.title')}
      </h2>
      <ol className={styles.lanes}>
        {CONTROL_ORDER.map((control) => {
          const lane = lanes[control];
          const resumed = control === 'D' && role === 'owner' && resumedItems !== null;
          const scored = score ? score.business[control] : undefined;
          const mark = scored ? (score?.correct[control] ?? null) : null;
          const tone = resumed ? 'safe' : toneOf(role, lane);
          const delivered = lane.kind === 'waiting' ? 0 : lane.delivered;
          const share = total > 0 ? Math.min(1, delivered / total) : 0;
          return (
            <li key={control} className={styles.lane} data-control={control} data-tone={tone}>
              <span className={styles.name}>{t(`control.${control}.name`)}</span>
              <span className={styles.config}>{t(`control.${control}.config`)}</span>
              <span className={styles.state}>
                {resumed
                  ? t(resumedBy === 'release' ? 'show.lane.released' : 'show.lane.resumed', {
                      n: (resumedItems ?? 0).toLocaleString(),
                    })
                  : stateText(role, lane, t)}
              </span>
              <progress className={styles.meter} max={1} value={share} aria-hidden="true" />
              <span className={styles.footer}>
                {lane.kind === 'done' ? (
                  <span className={styles.meta}>
                    {t('show.lane.meta', {
                      status: lane.httpStatus ?? '—',
                      seconds: secondsText(lane.elapsedMs),
                    })}
                  </span>
                ) : null}
                {scored ? (
                  <span className={styles.meta} data-part="score">
                    {t(`score.result.${scored.result}`, {
                      n: scored.exposedItems.toLocaleString(),
                      count: scored.exposedItems,
                    })}
                  </span>
                ) : null}
                {mark === true ? <span className={styles.right}>{t('exp.lane.right')}</span> : null}
                {mark === false ? <span className={styles.wrong}>{t('exp.lane.wrong')}</span> : null}
              </span>
              {onOpenEvidence && lane.kind === 'done' ? (
                <button type="button" className={styles.evidence} onClick={() => onOpenEvidence(control)}>
                  {t('show.lane.reasoning')}
                  <span className={styles.visuallyHidden}>{` — ${t(`control.${control}.name`)}`}</span>
                </button>
              ) : null}
            </li>
          );
        })}
      </ol>
    </section>
  );
}

type Tone = 'idle' | 'loss' | 'safe' | 'halt' | 'flow';

function toneOf(role: Role, lane: LaneState): Tone {
  if (lane.kind === 'waiting') {
    return 'idle';
  }
  if (lane.kind === 'streaming') {
    return role === 'attacker' ? 'loss' : 'flow';
  }
  switch (lane.outcome) {
    case 'DELIVERED':
      return role === 'attacker' ? 'loss' : 'safe';
    case 'CUT':
      return role === 'attacker' ? 'safe' : 'halt';
    case 'STOPPED':
      return role === 'attacker' ? 'safe' : 'halt';
    case 'HELD':
      return role === 'attacker' ? 'safe' : 'flow';
    case 'BROKEN':
      return role === 'attacker' ? 'loss' : 'halt';
    default:
      return 'idle';
  }
}

function stateText(role: Role, lane: LaneState, t: TFunction): string {
  if (lane.kind === 'waiting') {
    return t('show.lane.sending');
  }
  const n = lane.delivered.toLocaleString();
  if (lane.kind === 'streaming') {
    return role === 'attacker' ? t('show.lane.leaking', { n }) : t('show.lane.flowing', { n });
  }
  switch (lane.outcome) {
    case 'DELIVERED':
      return role === 'attacker' ? t('show.lane.leaked', { n }) : t('show.lane.done', { n });
    case 'CUT':
      return t('show.lane.cut', { n });
    case 'STOPPED':
      return role === 'attacker'
        ? t('show.lane.blocked', { n, count: lane.delivered })
        : t('show.lane.halted');
    case 'HELD':
      return t('show.lane.held');
    case 'BROKEN':
      return t('show.lane.broken', { n });
    default:
      return t('show.lane.unresolved');
  }
}
