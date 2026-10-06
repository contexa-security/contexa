import { useTranslation } from 'react-i18next';
import type { StepResult } from '../api/types';
import { reasonLine } from '../domain/evidence';
import type { Expectation, Lane } from '../domain/experience';
import { answerKey, isRight } from '../domain/experience';
import type { BusinessOutcome, ControlId } from '../domain/verdict';
import { CONTROL_ORDER, OUTCOME_KEYS } from '../domain/verdict';
import styles from './LaneBoard.module.css';

/**
 * Where the run stands: not sent yet, waiting in line, signing in, answers arriving, all in, stopped part-way, or a stored record shown
 * instead.
 */
export type BoardStatus = 'idle' | 'queued' | 'starting' | 'running' | 'done' | 'failed' | 'record';

interface LaneBoardProps {
  readonly lanes: Readonly<Record<ControlId, Lane>>;
  readonly status: BoardStatus;
  readonly queuePosition?: number | undefined;
  /** Date of the stored run shown as a record. */
  readonly recordedAt?: string | undefined;
  /** What the scene's request deserves; free play has none. */
  readonly expectation: Expectation | null;
  /** Contexa's identity check ended with the request served. */
  readonly servedAfterCheck?: boolean;
  /** Each control's outcome of the previous run in free play, to mark what changed. */
  readonly previous?: Readonly<Record<ControlId, BusinessOutcome>> | null;
  /** The full result once the run completed: each control's reason and its evidence one click away. */
  readonly result?: StepResult | null;
  readonly onOpenEvidence?: ((control: ControlId) => void) | undefined;
}

/**
 * The five security approaches answering the same request (deck p.10), one lane each in the order the request reaches
 * them. A lane waits, is being sent, then shows what happened to the data with the HTTP status and the time it took.
 */
export function LaneBoard({
  lanes,
  status,
  queuePosition,
  recordedAt,
  expectation,
  servedAfterCheck = false,
  previous = null,
  result = null,
  onOpenEvidence,
}: LaneBoardProps) {
  const { t, i18n } = useTranslation();
  const count = new Intl.NumberFormat(i18n.language === 'ko' ? 'ko-KR' : 'en-US');
  const finished = status === 'done' || status === 'record';
  const statusLine =
    status === 'queued'
      ? t('exp.lanes.queued', { position: queuePosition ?? 0 })
      : status === 'record'
        ? t('exp.lanes.record', { date: recordedAt ?? '' })
        : t(`exp.lanes.${status}`);

  return (
    <section className={styles.board} aria-live="polite" data-status={status}>
      <header className={styles.header}>
        <h3 className={styles.title}>{t('exp.lanes.title')}</h3>
        <p className={styles.status} role="status">
          {status === 'starting' || status === 'running' ? <span className={styles.pulse} aria-hidden="true" /> : null}
          {statusLine}
        </p>
      </header>
      <ol className={styles.lanes}>
        {CONTROL_ORDER.map((control) => {
          const lane = lanes[control];
          const layer = result?.layers.find((candidate) => candidate.control === control) ?? null;
          const served = control === 'D' && servedAfterCheck;
          const right =
            finished && expectation && lane.kind === 'done' ? isRight(lane.answer.outcome, expectation, served) : null;
          const before = previous?.[control];
          const changed = finished && lane.kind === 'done' && before !== undefined && before !== lane.answer.outcome;
          return (
            <li
              key={control}
              className={styles.lane}
              data-control={control}
              data-state={lane.kind}
              data-outcome={lane.kind === 'done' ? lane.answer.outcome : undefined}
            >
              <div className={styles.identity}>
                <span className={styles.name}>{t(`control.${control}.name`)}</span>
                <span className={styles.config}>{t(`control.${control}.config`)}</span>
              </div>
              <div className={styles.answer}>
                {lane.kind === 'waiting' ? <span className={styles.waiting}>{t('exp.lane.waiting')}</span> : null}
                {lane.kind === 'sending' ? (
                  <span className={styles.sending}>
                    <span className={styles.pulse} aria-hidden="true" />
                    {control === 'D' ? t('exp.lane.thinking') : t('exp.lane.sending')}
                  </span>
                ) : null}
                {lane.kind === 'done' ? (
                  <>
                    <span className={styles.outcome}>
                      {served
                        ? t('exp.lane.servedAfterCheck')
                        : t(answerKey(lane.answer), { items: count.format(lane.answer.deliveredItems) })}
                    </span>
                    <span className={styles.meta}>
                      {t('exp.lane.meta', {
                        status: lane.answer.httpStatus ?? '—',
                        ms: lane.answer.elapsedMs === null ? '—' : count.format(lane.answer.elapsedMs),
                      })}
                    </span>
                  </>
                ) : null}
              </div>
              <div className={styles.marks}>
                {right === true ? <span className={styles.right}>{t('exp.lane.right')}</span> : null}
                {right === false ? <span className={styles.wrong}>{t('exp.lane.wrong')}</span> : null}
                {finished && expectation && lane.kind === 'done' && right === null ? (
                  <span className={styles.neutral}>{t('exp.lane.noDecision')}</span>
                ) : null}
                {changed && before ? (
                  <span className={styles.changed}>{t('exp.lane.changed', { before: t(OUTCOME_KEYS[before]) })}</span>
                ) : null}
              </div>
              {layer && result ? (
                <div className={styles.detail}>
                  <p className={styles.reason}>{reasonLine(layer, result.engineReason, t)}</p>
                  {onOpenEvidence ? (
                    <button type="button" className={styles.evidence} onClick={() => onOpenEvidence(control)}>
                      {t('evidence.open')}
                      <span className={styles.visuallyHidden}>{` — ${t(`control.${control}.name`)}`}</span>
                    </button>
                  ) : null}
                </div>
              ) : null}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
