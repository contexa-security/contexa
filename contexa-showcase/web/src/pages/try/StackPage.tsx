import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useAnatomies, type DecisionAnatomyView } from '../../api/anatomy';
import { useJourney, useJourneyUpdate } from '../../api/journey';
import { useLabOptions, useRunStepResults } from '../../api/lab';
import { useMeasuredCase } from '../../api/measured';
import { useLiveRun } from '../../api/queries';
import { SourceMark } from '../../components/common/SourceMark';
import { Icon } from '../../components/Icon';
import { CumulativeMeter } from '../../components/inside/CumulativeMeter';
import { JustSaw } from '../../components/journey/JourneyParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { useRecordPath } from '../../components/replay/replayLine';
import { StateScreen } from '../../components/StateScreen';
import { VerdictChip } from '../../components/VerdictChip';
import { useLiveSend } from '../../hooks/useLiveSend';
import { count } from '../../journey/format';
import { useJourneyPlace } from '../../journey/useJourneyPlace';
import { meterRows, priorOf, verdictOf } from '../../components/inside/meterRows';
import experience from './Experience.module.css';
import styles from './StackPage.module.css';

/** Try 3's two cases (e3-stack, decision 1 of 15.3): the real work sent live, the attack replayed from the measurement. */
const WORK = 'A6T';
const ATTACK = 'A6';
const REQUESTS = 5;
/**
 * Try 3, requests build up (e3-stack, meter, 7.3): the same employee looks up customer records five times. The real
 * work is sent live by the visitor and its meter fills from the stored anatomies of each request; the attack is the
 * middle run of the current measurement, replayed and marked so. What the engine learned is the first and the last
 * request's records, not a screen's count.
 */
export default function StackPage() {
  const { t, i18n } = useTranslation();
  const recordPath = useRecordPath(WORK);
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const place = useJourneyPlace();
  const update = useJourneyUpdate();
  const options = useLabOptions();
  const journey = useJourney();
  const live = useLiveRun(true);
  const attackMeasured = useMeasuredCase(ATTACK).data ?? null;
  const sender = useLiveSend(WORK, () => undefined);
  const { turnstileContainer } = sender;
  const workCase = options.data?.cases.find((candidate) => candidate.key === WORK) ?? null;
  const employee = options.data?.employees.find(
    (candidate) => candidate.key === workCase?.conditions.employee,
  );
  const running =
    live.data?.scenario === WORK && !['COMPLETED', 'FAILED', 'EXPIRED'].includes(live.data.status);
  // The visitor's latest completed run of the real work; the live run counts as soon as it has ended, before the
  // journey has been read again, so the send button never comes back for a moment.
  const endedLive =
    live.data?.scenario === WORK && live.data.status === 'COMPLETED' ? (live.data.runId ?? null) : null;
  const workRun =
    [...(journey.data?.runs ?? [])]
      .reverse()
      .find((line) => line.scenarioKey === WORK && line.status === 'COMPLETED')?.runId ?? endedLive;
  const attackRun = attackMeasured?.middleRun ?? null;
  const workAnatomies = useAnatomies(running ? null : workRun, REQUESTS).map((query) => query.data);
  const workResults = useRunStepResults(running ? null : workRun, REQUESTS);
  const attackAnatomies = useAnatomies(attackRun, REQUESTS).map((query) => query.data);
  const attackResults = useRunStepResults(attackRun, REQUESTS);
  const workDone = workRun !== null && !running && workAnatomies.every((anatomy) => anatomy !== undefined);

  useEffect(() => {
    if (workDone && !place.differences.includes(6)) {
      void update({ difference: 6 });
    }
    // Seen once the visitor's own run is on screen; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workDone]);

  const first = (list: readonly (DecisionAnatomyView | undefined)[]) => list[0]?.figures;
  const last = (list: readonly (DecisionAnatomyView | undefined)[]) => list[list.length - 1]?.figures;
  const attackFirst = attackAnatomies[0];
  // What the attack let out over the run, as the portal scored that run.
  const attackOut = attackMeasured?.list.find((run) => run.runId === attackRun)?.exposedItems ?? null;

  return (
    <RouteScreen
      title={t('stack.title', { name: employee?.displayName ?? '' })}
      purpose={t('stack.purpose')}
      source={
        <SourceMark kind="ENGINE" runId={workRun ?? attackRun} step={null}>
          {t('stack.source', { attack: attackRun ?? '-' })}
        </SourceMark>
      }
      justSaw={workDone ? <JustSaw difference={6} sentence="e3Stack" /> : null}
      main={
        workRun === null && !running ? (
          <button
            type="button"
            className={experience.send}
            data-main
            disabled={!sender.ready}
            onClick={() => void sender.send()}
          >
            {sender.sending ? t('e1.predict.sending') : t('stack.send')}
            <Icon name="arrowRight" />
          </button>
        ) : running ? (
          <span className={styles.runningNote}>{t('stack.running')}</span>
        ) : undefined
      }
    >
      <section className={styles.lane} data-kind="work" aria-labelledby="stack-work">
        <h2 id="stack-work" className={styles.laneTitle}>
          <span className={styles.laneKind}>{t('stack.work.kind')}</span>
          {t('stack.work.name')}
          <span className={styles.laneTag}>{t('stack.live')}</span>
        </h2>
        {running && live.data ? (
          <ol className={styles.cells}>
            {Array.from({ length: REQUESTS }, (_, index) => {
              const layer = live.data?.steps.find((step) => step.stepNo === index + 1)?.layers.D ?? null;
              return (
                <li key={index} className={styles.cell} data-state={layer ? layer.outcome : 'waiting'}>
                  <span className={styles.cellNumber}>{index + 1}</span>
                  {layer
                    ? t(`stack.outcome.${layer.outcome}`, { defaultValue: layer.outcome })
                    : t('stack.waiting')}
                </li>
              );
            })}
          </ol>
        ) : null}
        {workDone ? (
          <>
            <CumulativeMeter
              caption={t('stack.meter')}
              rows={meterRows(workAnatomies, workResults)}
              pinned={false}
            />
            <p className={styles.summary}>
              {t('stack.work.summary', {
                observedFrom: first(workAnatomies)?.workProfileObservations ?? '-',
                observedTo: last(workAnatomies)?.workProfileObservations ?? '-',
                deltaFrom: first(workAnatomies)?.departureCount ?? '-',
                deltaTo: last(workAnatomies)?.departureCount ?? '-',
                learnedFrom: last(workAnatomies)?.baselineBefore ?? '-',
                learnedTo: last(workAnatomies)?.baselineAfter ?? '-',
              })}
            </p>
          </>
        ) : null}
        {workRun === null && !running ? <p className={styles.empty}>{t('stack.work.empty')}</p> : null}
      </section>
      <section className={styles.lane} data-kind="attack" aria-labelledby="stack-attack">
        <h2 id="stack-attack" className={styles.laneTitle}>
          <span className={styles.laneKind}>{t('stack.attack.kind')}</span>
          {t('stack.attack.name')}
          <span className={styles.laneTag}>{t('stack.replay')}</span>
        </h2>
        {attackAnatomies.every((anatomy) => anatomy !== undefined) && attackRun ? (
          <>
            <ol className={styles.cells}>
              {attackAnatomies.map((anatomy, index) => {
                const verdict = verdictOf(anatomy);
                return (
                  <li key={index} className={styles.cell} data-state={verdict ?? 'prior'}>
                    <span className={styles.cellNumber}>{index + 1}</span>
                    {verdict ? (
                      <VerdictChip verdict={verdict} />
                    ) : (
                      t(priorOf(attackResults[index]) ? 'stack.prior' : 'stack.notAnalysed')
                    )}
                  </li>
                );
              })}
            </ol>
            <p className={styles.summary}>
              {t('stack.attack.summary', {
                risk: attackFirst?.interpretation.recorded.riskScore ?? '-',
                verdict: t(`timing.verdict.${verdictOf(attackFirst) ?? 'NONE'}`),
                out: attackOut === null ? '-' : count(attackOut, language),
                learnedFrom: last(attackAnatomies)?.baselineBefore ?? '-',
                learnedTo: last(attackAnatomies)?.baselineAfter ?? '-',
              })}
            </p>
          </>
        ) : (
          <StateScreen kind="loading" />
        )}
      </section>
      <p className={styles.notice}>{t('stack.notice')}</p>
      {sender.waiting ? <p className={experience.lead}>{t('live.sendAfterEarlier')}</p> : null}
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
