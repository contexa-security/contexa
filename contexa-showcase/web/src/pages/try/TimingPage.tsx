import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useAnatomy } from '../../api/anatomy';
import { useJourney } from '../../api/journey';
import { useStepResult } from '../../api/lab';
import { useMeasuredCase, type MeasuredCase, type MeasuredRange } from '../../api/measured';
import { useLiveRun } from '../../api/queries';
import { ActionChip } from '../../components/common/ActionChip';
import { SourceMark } from '../../components/common/SourceMark';
import { Icon } from '../../components/Icon';
import { JustSaw } from '../../components/journey/JourneyParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { NextLink } from '../../components/journey/StepParts';
import { useRecordPath } from '../../components/replay/replayLine';
import { StateScreen } from '../../components/StateScreen';
import { useLiveSend } from '../../hooks/useLiveSend';
import { count, seconds } from '../../journey/format';
import { CASES } from './experience';
import experience from './Experience.module.css';
import styles from './TimingPage.module.css';

const STEPS = ['concept', 'try', 'compare', 'when'] as const;
type TimingStep = (typeof STEPS)[number];

/** A range of milliseconds in seconds, one value when both ends are the same. */
function secondsRange(range: MeasuredRange | null): string {
  if (!range) {
    return '-';
  }
  return range.min === range.max ? seconds(range.min) : `${seconds(range.min)}~${seconds(range.max)}`;
}

function itemsRange(range: MeasuredRange | null, language: string): string {
  if (!range) {
    return '-';
  }
  return range.min === range.max
    ? count(range.min, language)
    : `${count(range.min, language)}~${count(range.max, language)}`;
}

/** The measured run a screen shows as the example of a case: the one in the middle by analysis time. */
function middle(measured: MeasuredCase | null) {
  return measured?.list.find((run) => run.runId === measured.middleRun) ?? null;
}

/**
 * Synchronous and asynchronous, four screens (sync-concept, sync-try, sync-compare, sync-when, 7.3): the same export
 * on a time axis in the two modes, the visitor's own attack sent again asynchronously next to the synchronous one, the
 * measured two by two, and which mode fits which work. The two modes are the same export at two addresses (work 1);
 * every time and count is a stored run or the server's count of the current measurement.
 */
export default function TimingPage() {
  const { step = 'concept' } = useParams();
  if (!(STEPS as readonly string[]).includes(step)) {
    return <Navigate to="/try/timing/concept" replace />;
  }
  const current = step as TimingStep;
  return current === 'concept' ? (
    <Concept />
  ) : current === 'try' ? (
    <Resend />
  ) : current === 'compare' ? (
    <Compare />
  ) : (
    <When />
  );
}

function Legend() {
  const { t } = useTranslation();
  return (
    <ul className={experience.legend} aria-label={t('e1.run.legend.label')}>
      <li>
        <span className={experience.swatch} data-held="true" aria-hidden="true" />
        {t('timing.legend.held')}
      </li>
      <li>
        <span className={experience.swatch} data-outcome="DELIVERED" aria-hidden="true" />
        {t('timing.legend.out')}
      </li>
      <li>
        <span className={styles.swatchJudge} aria-hidden="true" />
        {t('timing.legend.judge')}
      </li>
    </ul>
  );
}

interface BarProps {
  readonly name: ReactNode;
  readonly ms: number;
  readonly max: number;
  readonly kind: 'held' | 'out' | 'judge';
  readonly label: string;
}

/** One row of the time axis: the bar's length is the stored time against the longest time on the screen. */
function Bar({ name, ms, max, kind, label }: BarProps) {
  return (
    <li className={experience.bar}>
      <span className={experience.barName}>{name}</span>
      <span className={experience.barTrack}>
        <span
          className={kind === 'judge' ? styles.judgeFill : experience.barFill}
          data-held={kind === 'held' || undefined}
          data-outcome={kind === 'out' ? 'DELIVERED' : undefined}
          style={{ width: `${Math.max(1, (ms / Math.max(1, max)) * 100)}%` }}
        />
      </span>
      <span className={experience.barLabel}>{label}</span>
    </li>
  );
}

/** T1, what is different (sync-concept): the measured example of each mode on one time axis. */
function Concept() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const sync = useMeasuredCase(CASES.attacker.sync).data ?? null;
  const async = useMeasuredCase(CASES.attacker.async).data ?? null;
  const syncRun = middle(sync);
  const asyncRun = middle(async);
  const max = Math.max(syncRun?.responseMs ?? 0, asyncRun?.analysisMs ?? 0, asyncRun?.responseMs ?? 0);
  const items = asyncRun?.exposedItems ?? syncRun?.exposedItems ?? null;
  return (
    <RouteScreen
      title={t('timing.concept.title', { items: items === null ? '-' : count(items, language) })}
      purpose={t('timing.concept.purpose')}
      source={
        sync && async ? (
          <SourceMark kind="MEASUREMENT" measured>
            {t('timing.concept.source', {
              protocol: sync.protocolId,
              sync: sync.middleRun ?? '-',
              async: async.middleRun ?? '-',
            })}
          </SourceMark>
        ) : null
      }
    >
      {!syncRun || !asyncRun ? (
        <StateScreen kind="loading" />
      ) : (
        <section className={styles.axisCard} aria-labelledby="timing-axis">
          <h2 id="timing-axis" className={styles.cardLabel}>
            {t('timing.concept.axis')}
          </h2>
          <Legend />
          <ol className={`${experience.bars} ${styles.timingBars}`}>
            <Bar
              name={<ModeName mode="sync" />}
              ms={syncRun.responseMs ?? 0}
              max={max}
              kind="held"
              label={t('timing.concept.sync', {
                seconds: seconds(syncRun.responseMs ?? 0),
                items: count(syncRun.exposedItems, language),
              })}
            />
            <Bar
              name={<ModeName mode="async" />}
              ms={asyncRun.responseMs ?? 0}
              max={max}
              kind="out"
              label={t('timing.concept.asyncOut', {
                seconds: seconds(asyncRun.responseMs ?? 0),
                items: count(asyncRun.exposedItems, language),
              })}
            />
            <Bar
              name={<span className={styles.subName}>{t('timing.concept.behind')}</span>}
              ms={asyncRun.analysisMs ?? 0}
              max={max}
              kind="judge"
              label={t('timing.concept.asyncJudge', { seconds: seconds(asyncRun.analysisMs ?? 0) })}
            />
          </ol>
          <p className={`${experience.axis} ${styles.timingAxis}`}>
            <span />
            <span className={styles.axisEnds}>
              <span>{t('timing.zero')}</span>
              <span>{t('timing.seconds', { seconds: seconds(max) })}</span>
            </span>
          </p>
        </section>
      )}
      <ul className={styles.meanings}>
        <li className={styles.meaning}>
          <span className={styles.meaningName}>{t('timing.mode.sync')}</span>
          {t('timing.concept.syncMeans')}
        </li>
        <li className={styles.meaning}>
          <span className={styles.meaningName}>{t('timing.mode.async')}</span>
          {t('timing.concept.asyncMeans')}
        </li>
      </ul>
    </RouteScreen>
  );
}

/** A mode's name with the one line of business code that chooses it. */
function ModeName({ mode }: { readonly mode: 'sync' | 'async' }) {
  const { t } = useTranslation();
  return (
    <span className={styles.modeName}>
      {t(`timing.mode.${mode}`)}
      <code className={styles.code} data-original>
        {mode === 'sync' ? '@Protectable(sync = true)' : '@Protectable'}
      </code>
    </span>
  );
}

interface RunCardProps {
  readonly label: string;
  readonly runId: string | null;
  readonly empty: string;
}

/** One stored run of the attack: what left, how long the response was held and what Contexa decided. */
function RunCard({ label, runId, empty }: RunCardProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const result = useStepResult(runId, 1).data ?? null;
  const anatomy = useAnatomy(runId, 1).data ?? null;
  const contexa = result?.layers.find((layer) => layer.control === 'D') ?? null;
  if (!runId) {
    return (
      <section className={styles.runCard} data-empty>
        <h2 className={styles.cardLabel}>{label}</h2>
        <p className={styles.runEmpty}>{empty}</p>
      </section>
    );
  }
  const delivered = contexa?.evidence.deliveredItems ?? null;
  return (
    <section className={styles.runCard} data-out={(delivered ?? 0) > 0 || undefined}>
      <h2 className={styles.cardLabel}>{label}</h2>
      {contexa ? (
        <>
          <span className={styles.runItems}>
            {t('timing.items', { items: delivered === null ? '-' : count(delivered, language) })}
          </span>
          <span className={styles.runLine}>
            {t('timing.try.response', {
              seconds: contexa.evidence.responseMs === null ? '-' : seconds(contexa.evidence.responseMs),
            })}
          </span>
          <span className={styles.runLine}>
            {t('timing.try.decision', {
              seconds:
                anatomy?.interpretation.timings.totalAnalysisMs == null
                  ? '-'
                  : seconds(anatomy.interpretation.timings.totalAnalysisMs),
              verdict: t(`timing.verdict.${contexa.verdict ?? 'NONE'}`),
              timing: t(`timing.applied.${contexa.evidence.timing ?? 'NONE'}`),
            })}
          </span>
        </>
      ) : (
        <StateScreen kind="loading" />
      )}
    </section>
  );
}

/**
 * T2, send it again (sync-try, D-34): the visitor's synchronous attack next to the same attack sent asynchronously.
 * Sending opens try 1's run step in the asynchronous mode, which comes back here when the run ends; from act 1 the main
 * button then returns to try 1.
 */
function Resend() {
  const { t } = useTranslation();
  const recordPath = useRecordPath(CASES.attacker.async);
  const [params] = useSearchParams();
  const fromAct1 = params.get('from') === 'attacker';
  const navigate = useNavigate();
  const journey = useJourney();
  const measured = useMeasuredCase(CASES.attacker.sync).data ?? null;
  const sender = useLiveSend(CASES.attacker.async, () => {
    void navigate(`/try/attacker/run?mode=async&from=timing${fromAct1 ? '-attacker' : ''}`);
  });
  const { turnstileContainer } = sender;
  const latest = (key: string) =>
    [...(journey.data?.runs ?? [])]
      .reverse()
      .find((line) => line.scenarioKey === key && line.status === 'COMPLETED')?.runId ?? null;
  // The resent run is shown by its number as soon as it exists; while it ends, this screen keeps watching it, so its
  // records are read again the moment it is complete.
  const live = useLiveRun(true);
  const liveAsync = live.data?.scenario === CASES.attacker.async ? live.data.runId : null;
  const syncRun = latest(CASES.attacker.sync) ?? measured?.middleRun ?? null;
  const asyncRun = latest(CASES.attacker.async) ?? liveAsync;
  const asyncResult = useStepResult(asyncRun, 1).data ?? null;
  const asyncOut = asyncResult?.layers.find((layer) => layer.control === 'D')?.evidence.deliveredItems ?? 0;

  const sendButton = (
    <button
      type="button"
      className={experience.send}
      data-main
      disabled={!sender.ready}
      onClick={() => void sender.send()}
    >
      {sender.sending ? t('e1.predict.sending') : t('timing.try.send')}
      <Icon name="arrowRight" />
    </button>
  );
  const main = !asyncRun ? (
    sendButton
  ) : fromAct1 ? (
    <NextLink to="/try/attacker/end" label={t('timing.try.backToAct1')} />
  ) : undefined;

  return (
    <RouteScreen
      title={t('timing.try.title')}
      purpose={t('timing.try.purpose')}
      source={
        syncRun ? (
          <SourceMark kind="ENGINE" runId={asyncRun ?? syncRun} step={1}>
            {t('timing.try.source', { sync: syncRun, async: asyncRun ?? '-' })}
          </SourceMark>
        ) : null
      }
      nextLabel={t('timing.try.next')}
      main={main}
      more={
        asyncRun ? (
          <ActionChip
            icon="refresh"
            variant="open"
            disabled={!sender.ready}
            onClick={() => void sender.send()}
          >
            {t('timing.try.again')}
          </ActionChip>
        ) : null
      }
    >
      <div className={styles.runCards}>
        <RunCard
          label={t(latest(CASES.attacker.sync) ? 'timing.try.syncOwn' : 'timing.try.syncMeasured')}
          runId={syncRun}
          empty="-"
        />
        <RunCard label={t('timing.try.asyncLabel')} runId={asyncRun} empty={t('timing.try.asyncEmpty')} />
      </div>
      {asyncRun && asyncOut > 0 ? <p className={experience.callout}>{t('timing.try.conclusion')}</p> : null}
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

/** T3, measured (sync-compare): attack and real work, synchronous and asynchronous, as the server counted them. */
function Compare() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const cells = {
    attackSync: useMeasuredCase(CASES.attacker.sync).data ?? null,
    attackAsync: useMeasuredCase(CASES.attacker.async).data ?? null,
    workSync: useMeasuredCase(CASES.owner.sync).data ?? null,
    workAsync: useMeasuredCase(CASES.owner.async).data ?? null,
  };
  const cell = (measured: MeasuredCase | null, threat: boolean, sync: boolean) =>
    measured ? (
      <div
        className={styles.cell}
        data-bad={(threat && (measured.exposedItems?.max ?? 0) > 0) || undefined}
        data-cost={(!threat && sync) || undefined}
      >
        <span className={styles.cellItems}>
          {t('timing.compare.items', { items: itemsRange(measured.exposedItems, language) })}
        </span>
        <span className={styles.runLine}>
          {sync
            ? t(threat ? 'timing.compare.syncAttack' : 'timing.compare.syncWork', {
                seconds: secondsRange(measured.responseMs),
              })
            : t(threat ? 'timing.compare.asyncAttack' : 'timing.compare.asyncWork', {
                seconds: secondsRange(measured.responseMs),
                judge: secondsRange(measured.analysisMs),
              })}
        </span>
      </div>
    ) : (
      <div className={styles.cell}>-</div>
    );
  return (
    <RouteScreen
      title={t('timing.compare.title')}
      purpose={t('timing.compare.purpose')}
      source={
        cells.attackSync ? (
          <SourceMark kind="MEASUREMENT" measured>
            {t('timing.compare.source', { protocol: cells.attackSync.protocolId })}
          </SourceMark>
        ) : null
      }
    >
      <table className={styles.grid}>
        <thead>
          <tr>
            <td />
            <th scope="col">
              <ModeName mode="sync" />
              <span className={styles.colHint}>{t('timing.compare.syncHint')}</span>
            </th>
            <th scope="col">
              <ModeName mode="async" />
              <span className={styles.colHint}>{t('timing.compare.asyncHint')}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <th scope="row">{t('timing.compare.attack')}</th>
            <td data-label={t('timing.mode.sync')}>{cell(cells.attackSync, true, true)}</td>
            <td data-label={t('timing.mode.async')}>{cell(cells.attackAsync, true, false)}</td>
          </tr>
          <tr>
            <th scope="row">{t('timing.compare.work')}</th>
            <td data-label={t('timing.mode.sync')}>{cell(cells.workSync, false, true)}</td>
            <td data-label={t('timing.mode.async')}>{cell(cells.workAsync, false, false)}</td>
          </tr>
        </tbody>
      </table>
      <ul className={styles.meanings}>
        <li className={styles.meaning}>
          <span className={styles.meaningName}>{t('timing.mode.sync')}</span>
          {t('timing.compare.syncTrade')}
        </li>
        <li className={styles.meaning}>
          <span className={styles.meaningName}>{t('timing.mode.async')}</span>
          {t('timing.compare.asyncTrade')}
        </li>
      </ul>
    </RouteScreen>
  );
}

/** T4, which when (sync-when): the two questions that choose the mode, what fits each with its measured cost. */
function When() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const work = useMeasuredCase(CASES.owner.sync).data ?? null;
  const repeated = useMeasuredCase('A6').data ?? null;
  const stream = useMeasuredCase('A3S').data ?? null;
  return (
    <RouteScreen
      title={t('timing.when.title')}
      purpose={t('timing.when.purpose')}
      source={
        work ? (
          <SourceMark kind="MEASUREMENT" measured>
            {t('timing.when.source', { protocol: work.protocolId })}
          </SourceMark>
        ) : null
      }
      justSaw={<JustSaw difference={1} sentence="syncWhen" />}
    >
      <ol className={styles.questions} aria-label={t('timing.when.flow')}>
        <li className={styles.question}>
          <span className={styles.questionText}>{t('timing.when.q1')}</span>
          <span className={styles.answer}>
            {t('timing.when.yes')}
            <Icon name="arrowRight" />
            <span className={styles.modeTag}>{t('timing.mode.sync')}</span>
          </span>
        </li>
        <li className={styles.question}>
          <span className={styles.questionText}>{t('timing.when.q2')}</span>
          <span className={styles.answer}>
            {t('timing.when.yes')}
            <Icon name="arrowRight" />
            <span className={styles.modeTag}>{t('timing.mode.async')}</span>
          </span>
        </li>
      </ol>
      <div className={styles.fits}>
        <section className={styles.fit} aria-labelledby="fit-sync">
          <h2 id="fit-sync" className={styles.fitName}>
            {t('timing.when.syncFits')}
          </h2>
          <p className={styles.fitWork}>{t('timing.when.syncWork')}</p>
          <dl className={styles.fitFacts}>
            <dt>{t('timing.when.demo')}</dt>
            <dd>{t('timing.when.syncDemo')}</dd>
            <dt>{t('timing.when.cost')}</dt>
            <dd>{t('timing.when.syncCost', { seconds: secondsRange(work?.responseMs ?? null) })}</dd>
          </dl>
        </section>
        <section className={styles.fit} aria-labelledby="fit-async">
          <h2 id="fit-async" className={styles.fitName}>
            {t('timing.when.asyncFits')}
          </h2>
          <p className={styles.fitWork}>{t('timing.when.asyncWork')}</p>
          <dl className={styles.fitFacts}>
            <dt>{t('timing.when.demo')}</dt>
            <dd>{t('timing.when.asyncDemo')}</dd>
            <dt>{t('timing.when.cost')}</dt>
            <dd>
              {t('timing.when.asyncCost', { items: itemsRange(repeated?.exposedItems ?? null, language) })}
            </dd>
          </dl>
        </section>
      </div>
      <p className={styles.caution}>
        <span className={styles.cautionName}>{t('timing.when.caution')}</span>
        {t('timing.when.cautionText', { items: itemsRange(stream?.exposedItems ?? null, language) })}
      </p>
    </RouteScreen>
  );
}
