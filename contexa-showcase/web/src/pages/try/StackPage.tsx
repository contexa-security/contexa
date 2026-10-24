import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useAnatomies, type DecisionAnatomyView } from '../../api/anatomy';
import { useJourney } from '../../api/journey';
import { useLabOptions, useRunStepResults } from '../../api/lab';
import { useMeasuredCase } from '../../api/measured';
import { useLiveRun } from '../../api/queries';
import type { LiveRunView, StepResult } from '../../api/types';
import { Icon } from '../../components/Icon';
import { priorOf, verdictOf } from '../../components/inside/meterRows';
import { routeFlow } from '../../components/journey/flow';
import { DetailChip, SourceLine } from '../../components/journey/FrameParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { useRecordPath } from '../../components/replay/replayLine';
import { StateScreen } from '../../components/StateScreen';
import { VERDICTS, type Verdict } from '../../domain/verdict';
import { useLiveSend } from '../../hooks/useLiveSend';
import { focusHeading } from '../../journey/focus';
import { count } from '../../journey/format';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import { latestRun, learnedText } from './learned';
import styles from './StackPage.module.css';

/** The two cases of screen 3-3: the real work the visitor sends live, and the attack from the current measurement. */
const WORK = 'A6T';
const ATTACK = 'A6';
/** A live run still going: in line, starting, answering, or waiting for the visitor (the portal's active states). */
const ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED', 'CONFIRMING']);

/** What one cell shows: Contexa's judgment of that request, what happened to it without one, or nothing yet. */
type Cell =
  | { readonly kind: 'verdict'; readonly verdict: Verdict }
  | { readonly kind: 'word'; readonly key: string }
  | { readonly kind: 'empty'; readonly key: string; readonly shown?: boolean };

/** A stored request: Contexa's own judgment, else what the request met (an earlier judgment, or its outcome). */
function recordedCell(anatomy: DecisionAnatomyView | undefined, result: StepResult | undefined): Cell {
  const verdict = verdictOf(anatomy);
  if (verdict) {
    return { kind: 'verdict', verdict };
  }
  if (priorOf(result)) {
    return { kind: 'word', key: 'p3.stack.cell.prior' };
  }
  const outcome = result?.layers.find((layer) => layer.control === 'D')?.outcome ?? null;
  return { kind: 'word', key: outcome ? `p3.stack.cell.${outcome}` : 'p3.stack.cell.none' };
}

/**
 * The last stored request of a run that could be read: the learned counts are the run's own (read when it started and
 * ended), so every request's record holds the same two; the last one is what the part's wrap-up reads too.
 */
function lastRecord(
  queries: readonly { readonly data: DecisionAnatomyView | undefined }[],
): DecisionAnatomyView | undefined {
  return [...queries].reverse().find((query) => query.data !== undefined)?.data;
}

/** A request of the run still going: its answer once it came, else a cell still waiting. */
function liveCell(view: LiveRunView | null, stepNo: number): Cell {
  const layer = view?.steps.find((step) => step.stepNo === stepNo)?.layers.D ?? null;
  return layer
    ? { kind: 'word', key: `p3.stack.cell.${layer.outcome}` }
    : { kind: 'empty', key: 'p3.stack.cell.waiting' };
}

interface LaneProps {
  readonly kind: 'work' | 'attack';
  readonly cells: readonly Cell[];
  /** The learned-requests line under the cells, or the lane's own state when there is no record to read. */
  readonly line: string | null;
  /** Whose record the cells are when it is not the visitor's own send (V-38). */
  readonly whose?: string | null;
}

/** One case as five cells that fill as its requests are answered, and what Contexa learned over them. */
function Lane({ kind, cells, line, whose = null }: LaneProps) {
  const { t } = useTranslation();
  const id = `stack-${kind}`;
  return (
    <section className={styles.lane} data-kind={kind} aria-labelledby={id}>
      <h2 id={id} className={styles.laneName}>
        <span className={styles.laneKind}>{t(`p3.stack.${kind}.name`)}</span>{' '}
        <span>{t(`p3.stack.${kind}.what`)}</span>
      </h2>
      {whose ? <p className={styles.whose}>{whose}</p> : null}
      <ol className={styles.cells} aria-label={t('p3.stack.cells')}>
        {cells.map((cell, index) => (
          <li
            key={index}
            className={styles.cell}
            data-state={cell.kind}
            data-verdict={cell.kind === 'verdict' ? cell.verdict : undefined}
          >
            <span className={styles.cellNumber}>{index + 1}</span>{' '}
            {cell.kind === 'verdict' ? (
              <span className={styles.mark}>
                <Icon name={VERDICTS[cell.verdict].icon} className={styles.markIcon} />
                <span>{t(VERDICTS[cell.verdict].labelKey)}</span>
              </span>
            ) : cell.kind === 'word' ? (
              <span className={styles.word}>{t(cell.key)}</span>
            ) : cell.shown ? (
              <span className={styles.faded}>{t(cell.key)}</span>
            ) : (
              <span className="visually-hidden">{t(cell.key)}</span>
            )}
          </li>
        ))}
      </ol>
      {line ? <p className={styles.learned}>{line}</p> : null}
    </section>
  );
}

/**
 * Screen 3-3, the same lookup sent five times (화면재편 T4): two rows of five cells, the real work the visitor sends
 * live and the attack as the current measurement recorded it, each with how many requests Contexa had learned when
 * its run started and ended. Sending is the main button until the visitor's run exists; while it goes the cells fill
 * as the answers come and there is no main button; once its records are stored the cells show Contexa's judgments
 * and the main button leads on. What each request's judgment rested on is in the decision details (one chip); the
 * cells are not pressable, so the body keeps within its limits (RC-1).
 */
export default function StackPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const position = useJourneyPosition();
  const flow = routeFlow(t, position);
  const recordPath = useRecordPath(WORK);
  const options = useLabOptions();
  const journey = useJourney();
  const live = useLiveRun(true);
  const attackMeasured = useMeasuredCase(ATTACK);
  const sender = useLiveSend(WORK, () => undefined);
  const { turnstileContainer } = sender;
  const requestsOf = (key: string) =>
    options.data?.cases.find((candidate) => candidate.key === key)?.requests.length ?? 0;
  const workSteps = requestsOf(WORK);
  const attackSteps = requestsOf(ATTACK);

  const ownLive = live.data?.scenario === WORK ? live.data : null;
  const active = ownLive !== null && ACTIVE.has(ownLive.status);
  const failed = ownLive !== null && (ownLive.status === 'FAILED' || ownLive.status === 'EXPIRED');
  // The run that has just ended counts before the journey is read again, so the send button never comes back.
  const endedLive = ownLive?.status === 'COMPLETED' ? ownLive.runId : null;
  const workRun = active ? null : (endedLive ?? latestRun(journey.data?.runs, WORK));
  const workQueries = useAnatomies(workRun, workSteps);
  const workResults = useRunStepResults(workRun, workSteps);
  const workStored = workRun !== null && workSteps > 0 && workQueries.every((query) => !query.isPending);
  // A run that has ended but whose records are still being read keeps filling from its live answers.
  const finishing = workRun !== null && workRun === endedLive && !workStored;
  const done = workStored;

  const attackRun = attackMeasured.data?.middleRun ?? null;
  const attackQueries = useAnatomies(attackRun, attackSteps);
  const attackResults = useRunStepResults(attackRun, attackSteps);
  const attackStored =
    attackRun !== null && attackSteps > 0 && attackQueries.every((query) => !query.isPending);

  useEffect(() => {
    if (done && !position.differences.includes(6)) {
      void position.see(6);
    }
    // Seen once the visitor's own run is on screen; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [done]);

  const loading = options.isPending || journey.isPending || live.isPending;
  const closed = sender.refusal === 'dailyLimit' || sender.refusal === 'paused';
  const canSend = !loading && !done && !active && !finishing && !closed;
  const steps = (n: number) => Array.from({ length: n }, (_, index) => index + 1);

  const workCells: readonly Cell[] = done
    ? steps(workSteps).map((stepNo) => recordedCell(workQueries[stepNo - 1]?.data, workResults[stepNo - 1]))
    : active || finishing
      ? steps(workSteps).map((stepNo) => liveCell(ownLive, stepNo))
      : steps(workSteps).map(() => ({ kind: 'empty', key: 'p3.stack.cell.unsent', shown: true }));
  const workLast = lastRecord(workQueries);
  const attackCells: readonly Cell[] = attackStored
    ? steps(attackSteps).map((stepNo) =>
        recordedCell(attackQueries[stepNo - 1]?.data, attackResults[stepNo - 1]),
      )
    : steps(attackSteps).map(() => ({
        kind: 'empty',
        key: attackMeasured.isPending || attackRun !== null ? 'p3.stack.cell.loading' : 'p3.stack.cell.none',
      }));
  const attackLast = lastRecord(attackQueries);
  const attackLine = attackStored
    ? learnedText(t, language, attackLast?.figures)
    : attackMeasured.isPending
      ? null
      : t('p3.stack.attack.none');
  // The learned state every send starts from, as the shown run's record holds it (P-32).
  const start = (done ? workLast : attackStored ? attackLast : undefined)?.figures?.baselineBefore ?? null;
  const reset =
    start === null ? t('p3.stack.resetPlain') : t('p3.stack.reset', { n: count(start, language) });

  const guide = done
    ? 'screen.3-3.guide'
    : closed
      ? 'p3.stack.guide.closed'
      : active || finishing
        ? 'p3.stack.guide.running'
        : failed
          ? 'p3.stack.guide.failed'
          : loading
            ? 'screen.3-3.guide'
            : 'p3.stack.guide.unsent';

  // Where the numbers come from: both rows once the visitor's run is stored, else only the attack row has any.
  const sourceLine = done ? (
    attackStored ? (
      <span>{t('p3.stack.source.both')}</span>
    ) : (
      <SourceLine kind="run" />
    )
  ) : attackStored ? (
    <SourceLine kind="earlier" />
  ) : null;
  const detailRun = done ? workRun : !active && !finishing && attackStored ? attackRun : null;

  const main = done ? (
    flow.next
  ) : closed ? (
    flow.next
  ) : canSend ? (
    <button
      type="button"
      className={styles.send}
      data-main
      disabled={!sender.ready}
      onClick={() => {
        void sender.send();
        // The button gives way to the running run; the focus goes to the headline, not to the page (RC-9).
        focusHeading();
      }}
    >
      {t(sender.sending ? 'p1.predict.sending' : 'p3.stack.send')}
      <Icon name="arrowRight" className={styles.sendIcon} />
    </button>
  ) : null;

  return (
    <RouteScreen
      title={t('screen.3-3.title')}
      purpose={t(guide)}
      sourceLine={sourceLine}
      more={detailRun ? <DetailChip runId={detailRun} /> : null}
      back={flow.back}
      main={main}
    >
      {loading ? (
        <StateScreen kind="loading" />
      ) : (
        <>
          {ownLive?.status === 'QUEUED' ? (
            <StateScreen
              kind="queued"
              queuePosition={ownLive.queuePosition}
              remainingSeconds={ownLive.queueWaitSeconds}
            />
          ) : null}
          {ownLive?.status === 'STARTING' ? <p className={styles.note}>{t('e1.run.preparing')}</p> : null}
          <Lane
            kind="work"
            cells={workCells}
            line={done ? learnedText(t, language, workLast?.figures) : null}
          />
          <Lane
            kind="attack"
            cells={attackCells}
            line={attackLine}
            whose={attackStored ? t('p3.stack.attack.earlier') : null}
          />
          {/* Kept from the old screen (facts always stay): the demo starts each run from the same learning. */}
          <p className={styles.note}>{reset}</p>
        </>
      )}
      {sender.waiting ? <p className={styles.note}>{t('p1.predict.waitEarlier')}</p> : null}
      {sender.turnstileRequired ? <div ref={turnstileContainer} /> : null}
      {sender.refusal ? (
        <StateScreen
          kind={closed ? (sender.refusal === 'dailyLimit' ? 'dailyLimit' : 'paused') : 'outage'}
          recordTo={recordPath}
          {...(sender.refusal === 'error' || sender.refusal === 'turnstile'
            ? { onRetry: () => void sender.send() }
            : {})}
        />
      ) : null}
    </RouteScreen>
  );
}
