import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router-dom';
import { useAnatomy } from '../../../api/anatomy';
import { useJourney } from '../../../api/journey';
import { useLabOptions, useStepResult } from '../../../api/lab';
import { useMeasuredCase } from '../../../api/measured';
import { useLiveRun } from '../../../api/queries';
import type { Timing } from '../../../api/types';
import { useDetail } from '../../../components/detail/useDetail';
import { Icon } from '../../../components/Icon';
import { routeFlow } from '../../../components/journey/flow';
import { RouteScreen } from '../../../components/journey/RouteScreen';
import { useRecordPath } from '../../../components/replay/replayLine';
import { StateScreen } from '../../../components/StateScreen';
import { VerdictChip } from '../../../components/VerdictChip';
import { useLiveSend } from '../../../hooks/useLiveSend';
import { count, seconds } from '../../../journey/format';
import { useJourneyPosition } from '../../../journey/useJourneyPosition';
import { caseOf } from '../../main/mainCases';
import { CASES } from '../experience';
import experience from '../Experience.module.css';
import styles from './Timing.module.css';

/** The live statuses of a run still going; the screen then points to it instead of sending another. */
const GOING = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED', 'CONFIRMING']);

/** The run step the attack sent "from the next request" opens; it comes back here when the run ends. */
const RUN_STEP = '/try/attacker/run?mode=async&from=timing';

/** The value a faint line holds before there is a record: none, as the screens write a missing value. */
const BLANK = '—';

/** When the judgment applied, in plain words (화면재편-기획안 11.2); the record's code picks the words. */
const APPLIED: Readonly<Record<Timing, string>> = {
  BEFORE_RESPONSE: 'p4.applied.BEFORE_RESPONSE',
  NEXT_REQUEST: 'p4.applied.NEXT_REQUEST',
  MID_RESPONSE: 'p4.applied.MID_RESPONSE',
  NONE: 'p4.applied.NONE',
  PRIOR_DECISION: 'p4.applied.PRIOR_DECISION',
  STATIC_AUTHORIZATION: 'p4.applied.STATIC_AUTHORIZATION',
  NOT_ANALYSED: 'p4.applied.NOT_ANALYSED',
};

interface RunCardProps {
  /** The way the run was sent: the card's name. */
  readonly mode: 'sync' | 'async';
  /** The case the run sent: its definition tells whether the run sent a next request at all. */
  readonly caseKey: string;
  /** Whose request it is: the visitor's earlier one, the same request sent earlier, or the one just sent. */
  readonly whose: string;
  readonly runId: string | null;
  /** What the card says when there is no run to show. */
  readonly empty: string;
  /** What the visitor can do there while the card is empty: send the request, or watch the one being sent. */
  readonly action?: ReactNode;
  /** While empty, show faintly the lines the result will fill (L-11), for the request still to be sent. */
  readonly ghost?: boolean;
}

/**
 * One request of the attack in one way: what went out, when the answer came, Contexa's judgment, how long it took and
 * when it applied, and, where the run sent one, what happened to the next request. Every value is the stored record of
 * that run; the card never works one out.
 */
function RunCard({ mode, caseKey, whose, runId, empty, action = null, ghost = false }: RunCardProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const steps = caseOf(useLabOptions().data, caseKey)?.labCase.steps ?? 0;
  const first = useStepResult(runId, 1);
  // Only a case with a second step has a next request to read.
  const next = useStepResult(steps >= 2 ? runId : null, 2);
  const anatomy = useAnatomy(runId, 1).data ?? null;
  const contexa = first.data?.layers.find((layer) => layer.control === 'D') ?? null;
  const nextContexa = next.data?.layers.find((layer) => layer.control === 'D') ?? null;
  const analysisMs = anatomy?.interpretation.timings.totalAnalysisMs ?? null;
  const out = contexa?.outcome === 'DELIVERED';
  const timing = contexa?.evidence.timing ?? null;

  return (
    // One block for the gap check: a card's lines belong together (data-block).
    <section className={styles.card} aria-labelledby={`timing-${mode}`} data-block>
      <h2 id={`timing-${mode}`} className={styles.cardName}>
        {t(`p4.mode.${mode}`)}
      </h2>
      <p className={styles.whose}>{whose}</p>
      {!runId ? (
        <>
          <p className={styles.line}>{empty}</p>
          {ghost ? (
            // The lines of a result with no value in them, drawing only: a screen reader hears the line above.
            <div className={styles.ghost} aria-hidden="true" data-ghost>
              <p className={styles.items}>{t('p4.items', { items: BLANK })}</p>
              <p className={styles.line}>{t('p4.response', { seconds: BLANK })}</p>
              <p className={styles.judged}>{t('p4.judged', { seconds: BLANK, applied: BLANK })}</p>
            </div>
          ) : null}
          {action}
        </>
      ) : contexa ? (
        <>
          <p className={styles.items} data-out={out || undefined}>
            {t('p4.items', { items: count(contexa.evidence.deliveredItems, language) })}
          </p>
          <p className={styles.line}>
            {t('p4.response', {
              seconds: contexa.evidence.responseMs === null ? '-' : seconds(contexa.evidence.responseMs),
            })}
          </p>
          <p className={styles.judged}>
            {contexa.verdict ? (
              <VerdictChip verdict={contexa.verdict} unresolved={contexa.evidence.unresolved} />
            ) : null}
            <span>
              {t('p4.judged', {
                seconds: analysisMs === null ? '-' : seconds(analysisMs),
                applied: t(timing ? APPLIED[timing] : 'p4.applied.unknown'),
              })}
            </span>
          </p>
          {nextContexa ? (
            <p className={styles.line}>
              {t(nextContexa.outcome === 'DELIVERED' ? 'p4.try.next.out' : 'p4.try.next.stopped')}
            </p>
          ) : null}
        </>
      ) : first.isPending ? (
        <p className={styles.line}>{t('state.loading')}</p>
      ) : (
        <p className={styles.line}>{t('p4.none')}</p>
      )}
    </section>
  );
}

/**
 * Screen 4-1, sending it the other way (화면재편 T4): the two results side by side, the attack the visitor sent before,
 * stopped before the response (1-3, or the same request sent earlier when they skipped it), and the same attack sent
 * now with "stop from the next request" (A3A), whose card holds Send until it is sent. Sending opens the run as the
 * try's run step does, which comes back here when it ends; only then the main button leads to the result. The "send
 * again" chip is gone (R-2).
 */
export default function ResendScreen() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const detail = useDetail();
  const position = useJourneyPosition();
  const flow = routeFlow(t, position);
  const number = position.screen?.number ?? '4-1';
  const recordPath = useRecordPath(CASES.attacker.async);
  const journey = useJourney();
  const measured = useMeasuredCase(CASES.attacker.sync).data ?? null;
  const live = useLiveRun(true);
  const sender = useLiveSend(CASES.attacker.async, () => {
    void navigate(RUN_STEP);
  });
  const { turnstileContainer } = sender;

  const latest = (key: string) =>
    [...(journey.data?.runs ?? [])]
      .reverse()
      .find((line) => line.scenarioKey === key && !line.lab && line.status === 'COMPLETED')?.runId ?? null;
  const liveAsync = live.data?.scenario === CASES.attacker.async ? live.data : null;
  const going = liveAsync !== null && GOING.has(liveAsync.status);
  const ownSync = latest(CASES.attacker.sync);
  const syncRun = ownSync ?? measured?.middleRun ?? null;
  const sentRun =
    latest(CASES.attacker.async) ?? (liveAsync?.status === 'COMPLETED' ? liveAsync.runId : null);
  const asyncRun = going ? null : sentRun;

  // One source line for the screen: both requests the visitor's, or the earlier one recorded and the new one theirs.
  const sourceKey = asyncRun
    ? ownSync || !syncRun
      ? 'frame.source.run'
      : 'p4.try.source.mixed'
    : syncRun
      ? ownSync
        ? 'frame.source.run'
        : 'frame.source.earlier'
      : null;
  const opened = asyncRun ?? syncRun;

  // The one main button (R-2, as on 1-2 and 3-3): send, or watch the request being sent, until there is a result; then
  // it leads to the next screen.
  const action = going ? (
    <Link to={RUN_STEP} className={styles.watch} data-main>
      {t('p4.try.watch')}
    </Link>
  ) : (
    <button
      type="button"
      className={`${experience.send} ${styles.send}`}
      data-main
      disabled={!sender.ready}
      onClick={() => void sender.send()}
    >
      {t(sender.sending ? 'p1.predict.sending' : 'p1.predict.send')}
      <Icon name="arrowRight" />
    </button>
  );

  return (
    <RouteScreen
      title={t(`screen.${number}.title`)}
      purpose={t(`screen.${number}.guide`)}
      sourceLine={
        sourceKey && opened ? (
          <>
            <span>{t(sourceKey)}</span>
            <button type="button" className={styles.sourceOpen} onClick={() => detail.show(opened, 1)}>
              {t('frame.source.open')}
            </button>
          </>
        ) : null
      }
      back={flow.back}
      main={asyncRun ? flow.next : action}
    >
      <div className={styles.cards}>
        <RunCard
          mode="sync"
          caseKey={CASES.attacker.sync}
          whose={t(ownSync ? 'p4.try.own' : 'p4.try.record')}
          runId={syncRun}
          empty={t('p4.none')}
        />
        <RunCard
          mode="async"
          caseKey={CASES.attacker.async}
          whose={t('p4.try.now')}
          runId={asyncRun}
          empty={t(going ? 'p4.try.going' : 'p4.try.notSent')}
          ghost
        />
      </div>
      {sender.waiting ? <p className={styles.note}>{t('p1.predict.waitEarlier')}</p> : null}
      {sender.turnstileRequired ? <div ref={turnstileContainer} /> : null}
      {sender.refusal ? (
        <StateScreen
          kind={
            sender.refusal === 'dailyLimit' ? 'dailyLimit' : sender.refusal === 'paused' ? 'paused' : 'outage'
          }
          recordTo={recordPath}
          {...(sender.refusal === 'error' || sender.refusal === 'turnstile'
            ? { onRetry: () => void sender.send() }
            : {})}
        />
      ) : null}
    </RouteScreen>
  );
}
