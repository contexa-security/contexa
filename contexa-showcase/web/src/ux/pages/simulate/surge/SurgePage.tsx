import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { useAgentCase, useAgentRun, useAgentTry, type BurstSummary } from '../../../../api/agentCase';
import { useBurstSnapshots, type BurstPair } from '../../../../api/agentSnapshots';
import { useAnatomies } from '../../../../api/anatomy';
import { postJson } from '../../../../api/http';
import { useLabOptions, useRunStepResults } from '../../../../api/lab';
import { useMeasuredCase } from '../../../../api/measured';
import { useLiveConfig } from '../../../../api/queries';
import type { LiveRunView } from '../../../../api/types';
import { priorOf, verdictOf } from '../../../simulate/meterRows';
import { useLiveSend } from '../../../../hooks/useLiveSend';
import { formatNumber, formatUtc } from '../../../format';
import { agentCell, chainResource } from '../../../simulate/agent';
import { AgentSteps, DelegationChain, Instruction, SenderBadge } from '../../../simulate/AgentParts';
import { useRecordRows } from '../../../simulate/agentRows';
import { GroupTabs } from '../../../simulate/FlowFrame';
import { PERSON_KEYS } from '../../../simulate/person';
import { useGroupRuns } from '../../../simulate/useFlow';
import {
  Badge,
  Button,
  CodeChip,
  Loading,
  Modal,
  Note,
  PageHead,
  Stepper,
  TabPanel,
  Tabs,
  VerdictBadge,
} from '../../../ui';
import review from '../../../simulate/Review.module.css';
import styles from '../../../simulate/Agent.module.css';

/** A live run still going or waiting for the visitor (the portal's active states). */
const ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED', 'CONFIRMING']);
const ENDED = new Set(['FAILED', 'EXPIRED']);
/** The numbers a visitor may pick for a live burst, never above what the portal allows (DEC-30). */
const PRESETS = [1, 3, 5, 10];
/** The repeated read (옛 M-stack): the real work the visitor sends live, and the attack from the measurement. */
const WORK = 'A6T';
const ATTACK = 'A6';

type TabId = 'burst' | 'repeat';

/**
 * Request surge handling (기획안 7.6, DEC-30 · DEC-31): the same request of a business agent arriving many at once.
 * The visitor sends up to ten live and sees the counts fill; the stored real measurements of sixty show what merging
 * the decisions of the same request (flights) does to model calls. The second tab is the repeated read: the same
 * lookup five times as normal work, beside the attack that repeats it (옛 M-stack).
 */
export default function SurgePage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const live = useLiveConfig();
  const tab: TabId = params.get('tab') === 'repeat' ? 'repeat' : 'burst';
  const select = (id: string) => {
    const next = new URLSearchParams(params);
    next.set('tab', id);
    setParams(next, { replace: true });
  };
  return (
    <>
      <PageHead title={t('ux.surge.title')} desc={t('ux.surge.desc')} />
      <GroupTabs
        current="surge"
        counts={{
          person: PERSON_KEYS.length,
          agent: live.data?.agentCases?.length ?? null,
          surge: live.data ? (live.data.burst ? 1 : 0) : null,
        }}
      />
      <Tabs
        idBase="surge"
        label={t('ux.surge.tabs')}
        value={tab}
        onChange={select}
        items={[
          { id: 'burst', label: t('ux.surge.tab.burst') },
          { id: 'repeat', label: t('ux.surge.tab.repeat') },
        ]}
      />
      <TabPanel idBase="surge" id={tab}>
        {tab === 'burst' ? <BurstTab /> : <RepeatTab />}
      </TabPanel>
    </>
  );
}

function BurstTab() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const n = (value: number) => formatNumber(value, i18n.language);
  const config = useLiveConfig();
  const burst = config.data?.burst ?? null;
  const caseKey = burst?.case ?? null;
  const agentCase = useAgentCase(caseKey ?? '', undefined, caseKey !== null);
  const stored = useBurstSnapshots();
  const tried = useAgentTry(caseKey ?? '');
  const runs = useGroupRuns(caseKey ? [caseKey] : []);
  const view: LiveRunView | null = tried.live;
  const active = view !== null && ACTIVE.has(view.status);
  const failed = view !== null && ENDED.has(view.status);
  const finishedId = !active && !failed ? tried.runId : null;
  const own = useAgentRun(finishedId).data?.burst ?? null;
  const most = burst?.most ?? 10;
  const choices = [...PRESETS.filter((value) => value < most), most];
  const [picked, setPicked] = useState<number | null>(null);
  const copies = picked ?? most;
  const [confirming, setConfirming] = useState(false);
  const { send, sending, ready, refusal, reason, waiting, turnstileContainer, turnstileRequired } = useLiveSend(
    caseKey ?? '',
    () => undefined,
    {
      post: (turnstileToken) =>
        postJson<LiveRunView & { reason?: string }>('/api/live/runs', {
          scenario: caseKey,
          turnstileToken,
          copies,
        }),
    },
  );
  if (config.isPending) {
    return <Loading rows={6} />;
  }
  if (!burst || !caseKey) {
    return <Note>{t('ux.surge.none')}</Note>;
  }
  const agentsLeft = config.data?.remainingAgentToday ?? null;
  const tickets = config.data?.liveTicketsLeft ?? null;
  const points = config.data?.remainingToday ?? null;
  const why = !runs.visitorReady
    ? t('ux.review.reason.visitor')
    : agentsLeft === 0
      ? t('ux.agentReview.reason.agentLimit')
      : tickets !== null && tickets <= 0
        ? t('ux.agentReview.reason.tickets')
        : points !== null && points < burst.points
          ? t('ux.surge.reason.points', { n: burst.points })
          : active
            ? t('ux.surge.reason.active')
            : turnstileRequired && !ready && !sending && !waiting
              ? t('ux.review.reason.human')
              : undefined;
  const pair = stored.bursts.find((item) => item.burst === caseKey) ?? null;
  const others = stored.bursts.filter((item) => item.burst !== caseKey);
  const step = active || sending || waiting ? 1 : own ? 2 : 0;
  const data = agentCase.data ?? null;
  return (
    <>
      <Stepper
        steps={[t('ux.surge.step.compose'), t('ux.surge.step.send'), t('ux.surge.step.result')]}
        current={step}
      />
      <section className={styles.section} aria-labelledby="surge-compose">
        <h2 id="surge-compose" className={styles.sectionTitle}>
          <span className={styles.sectionNo}>1</span>
          {t('ux.surge.step.compose')}
        </h2>
        <div className={styles.review}>
          <div className={styles.reviewMain}>
            <p className={styles.check}>{burst.title[language] ?? burst.title.en ?? caseKey}</p>
            {data ? (
              <>
                <p className={styles.caseLine}>
                  <SenderBadge sender={data.sender} />
                </p>
                <DelegationChain
                  delegator={t(`ux.person.${data.protagonist}`, { defaultValue: data.protagonist })}
                  agent={data.agentTitle[language] ?? data.agentName}
                  resource={chainResource(data.delegation)}
                />
                <Instruction text={data.instruction[language] ?? data.instruction.en ?? ''} />
              </>
            ) : (
              <Loading rows={2} />
            )}
            <p className={styles.sectionDesc}>{t('ux.surge.composeNote', { measured: n(burst.measured) })}</p>
          </div>
          <div className={styles.reviewSide}>
            <div>
              <p className={styles.cellsHead} id="surge-count">
                {t('ux.surge.count')}
              </p>
              <div role="radiogroup" aria-labelledby="surge-count" className={styles.burstChoices}>
                {choices.map((value) => (
                  <button
                    key={value}
                    type="button"
                    role="radio"
                    aria-checked={copies === value}
                    className={styles.burstChoice}
                    onClick={() => setPicked(value)}
                  >
                    {t('ux.facts.items', { count: value, n: n(value) })}
                  </button>
                ))}
              </div>
            </div>
            {turnstileRequired ? <div ref={turnstileContainer} className={review.turnstile} /> : null}
            <div className={styles.runButton}>
              <Button
                variant="primary"
                size="lg"
                icon="layers"
                busy={sending || waiting}
                {...(why ? { disabledReason: why } : {})}
                onClick={() => setConfirming(true)}
              >
                {t('ux.surge.send', { n: n(copies) })}
              </Button>
            </div>
            <ul className={styles.sideMeta}>
              <li>{t('ux.agentReview.realAgent')}</li>
              {config.data?.dailyAgentRuns != null && agentsLeft !== null ? (
                <li>{t('ux.agentReview.daily', { n: n(config.data.dailyAgentRuns), left: n(agentsLeft) })}</li>
              ) : null}
            </ul>
          </div>
        </div>
        {waiting ? <Note icon="hourglass">{t('ux.review.waiting')}</Note> : null}
        {refusal ? (
          <Note tone="warn">
            {refusal === 'dailyLimit' && (reason === 'AGENT_LIMIT' || agentsLeft === 0)
              ? t('ux.agentReview.refusal.agentLimit')
              : t(`ux.review.refusal.${refusal}`)}
          </Note>
        ) : null}
      </section>

      <Modal
        open={confirming}
        onClose={() => setConfirming(false)}
        title={t('ux.surge.confirm.title', { n: n(copies) })}
        size="sm"
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirming(false)}>
              {t('ux.action.cancel')}
            </Button>
            <Button
              variant="primary"
              icon="layers"
              onClick={() => {
                setConfirming(false);
                void send();
              }}
            >
              {t('ux.surge.send', { n: n(copies) })}
            </Button>
          </>
        }
      >
        <p className={styles.sectionDesc}>{t('ux.surge.confirm.body', { n: n(copies), points: n(burst.points) })}</p>
      </Modal>

      {view !== null || own ? (
        <section className={styles.section} aria-labelledby="surge-send">
          <h2 id="surge-send" className={styles.sectionTitle}>
            <span className={styles.sectionNo}>2</span>
            {t('ux.surge.step.send')}
            {view?.runId ?? finishedId ? <CodeChip value={(view?.runId ?? finishedId) as string} copy /> : null}
          </h2>
          {failed ? <Note tone="warn">{t('ux.surge.failed')}</Note> : <Counters view={view} own={own} />}
        </section>
      ) : null}

      <section className={styles.section} aria-labelledby="surge-result">
        <h2 id="surge-result" className={styles.sectionTitle}>
          <span className={styles.sectionNo}>3</span>
          {t('ux.surge.step.result')}
        </h2>
        <p className={styles.sectionDesc}>{t('ux.surge.resultDesc')}</p>
        {stored.pending ? <Loading rows={4} /> : <Comparison own={own} pair={pair} />}
        {others.length > 0 ? <OtherBursts pairs={others} /> : null}
      </section>
    </>
  );
}

/** What can be counted while the burst is followed live (DEC-31); the model calls come once the run is stored. */
function Counters({ view, own }: { readonly view: LiveRunView | null; readonly own: BurstSummary | null }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const cells = (view?.steps ?? []).map((step) => agentCell(step.layers.D ?? null));
  const arrived = own?.requests ?? cells.length;
  const delivered = own?.delivered ?? cells.filter((cell) => cell === 'ALLOW').length;
  const refused = own?.refused ?? cells.filter((cell) => cell !== null && cell !== 'ALLOW' && cell !== 'PENDING').length;
  const calls = own?.modelCalls ?? null;
  return (
    <dl className={styles.counters} aria-live="polite">
      <div className={styles.counter}>
        <dt>{t('ux.surge.row.requests')}</dt>
        <dd>{n(arrived)}</dd>
      </div>
      <div className={styles.counter}>
        <dt>{t('ux.surge.row.delivered')}</dt>
        <dd>{n(delivered)}</dd>
      </div>
      <div className={styles.counter}>
        <dt>{t('ux.surge.row.refused')}</dt>
        <dd>{n(refused)}</dd>
      </div>
      <div className={styles.counter}>
        <dt>{t('ux.surge.row.modelCalls')}</dt>
        <dd>
          {calls === null ? <span className={styles.counterNote}>{t('ux.surge.afterStored')}</span> : n(calls)}
        </dd>
      </div>
    </dl>
  );
}

/** A burst's counts as the portal made them from the run's steps (AS-10, AS-13), the first stop among them (옛 6-6). */
const ROWS = [
  'requests',
  'delivered',
  'refused',
  'busy',
  'withVerdict',
  'modelCalls',
  'deliveredAfterFirstStop',
  'firstStopStep',
] as const;

/** One burst's counts: the visitor's own (when sent) beside the stored measurement with merging on and off. */
function BurstTable({
  caption,
  own,
  pair,
}: {
  readonly caption: string;
  readonly own: BurstSummary | null;
  readonly pair: BurstPair;
}) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const value = (summary: BurstSummary, row: (typeof ROWS)[number]) =>
    row !== 'firstStopStep'
      ? n(summary[row])
      : summary.firstStopStep === null
        ? t('ux.agentResult.controls.never')
        : t('ux.pick.requestNo', { n: summary.firstStopStep });
  return (
    <div className={styles.countsScroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
      <table className={styles.counts}>
        <caption className="ux-sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">{t('ux.surge.row.label')}</th>
            {own ? <th scope="col">{t('ux.surge.col.own', { n: n(own.requests) })}</th> : null}
            <th scope="col">{t('ux.surge.col.on')}</th>
            <th scope="col">{t('ux.surge.col.off')}</th>
          </tr>
        </thead>
        <tbody>
          {ROWS.map((row) => (
            <tr key={row} data-contexa={row === 'modelCalls' || undefined}>
              <th scope="row">{t(`ux.surge.row.${row}`)}</th>
              {own ? <td>{value(own, row)}</td> : null}
              <td>{value(pair.on.summary, row)}</td>
              <td>{value(pair.off.summary, row)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Where a stored measurement comes from: its two runs, and when the run with merging on was stored. */
function Source({ pair }: { readonly pair: BurstPair }) {
  const { t } = useTranslation();
  return (
    <p className={styles.counterNote}>
      {t('ux.surge.source')} <CodeChip value={pair.on.runId} /> <CodeChip value={pair.off.runId} />{' '}
      {t('ux.surge.capturedAt', { at: `${formatUtc(pair.on.capturedAt)} ${t('ux.runs.utc')}` })}
    </p>
  );
}

/** The visitor's burst beside the stored measurement of sixty, with the merging of decisions on and off. */
function Comparison({ own, pair }: { readonly own: BurstSummary | null; readonly pair: BurstPair | null }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const onRows = useRecordRows(pair?.on.run);
  if (!pair) {
    return <Note>{t('ux.surge.noMeasurement')}</Note>;
  }
  const on = pair.on.summary;
  const off = pair.off.summary;
  const same = on.delivered === off.delivered;
  return (
    <section className={styles.panel} aria-labelledby={`surge-case-${pair.burst}`}>
      <header className={styles.panelHead}>
        <h3 id={`surge-case-${pair.burst}`} className={styles.panelTitle}>
          {t(`ux.surge.case.${pair.burst}`, { defaultValue: pair.burst })}
        </h3>
      </header>
      <BurstTable caption={t('ux.surge.step.result')} own={own} pair={pair} />
      <div className={styles.panelBody}>
        {own ? (
          <p className={styles.sectionDesc}>
            {own.withVerdict + own.busy >= own.requests
              ? t('ux.surge.ownNotMerged', { n: n(own.requests) })
              : t('ux.surge.ownMerged', { n: n(own.requests - own.withVerdict - own.busy), calls: n(own.modelCalls) })}
          </p>
        ) : null}
        <p className={styles.check}>
          {t(same ? 'ux.surge.insight.same' : 'ux.surge.insight.differs', {
            requests: n(on.requests),
            off: n(off.modelCalls),
            on: n(on.modelCalls),
            delivered: n(on.delivered),
            deliveredOff: n(off.delivered),
          })}
        </p>
        <Source pair={pair} />
        {onRows.length > 0 ? (
          <details className={styles.more}>
            <summary>{t('ux.surge.timeline')}</summary>
            <AgentSteps rows={onRows} caption={t('ux.surge.timeline')} decisions />
          </details>
        ) : null}
      </div>
    </section>
  );
}

/** The two other stored bursts: sensitive records and exports outside the delegation, each with merging on and off. */
function OtherBursts({ pairs }: { readonly pairs: readonly BurstPair[] }) {
  const { t } = useTranslation();
  return (
    <details className={styles.panel}>
      <summary className={styles.panelHead}>{t('ux.surge.others', { n: pairs.length })}</summary>
      {pairs.map((pair) => {
        const name = t(`ux.surge.case.${pair.burst}`, { defaultValue: pair.burst });
        return (
          <section key={pair.burst} className={styles.otherBurst} aria-labelledby={`surge-case-${pair.burst}`}>
            <h3 id={`surge-case-${pair.burst}`} className={styles.panelTitle}>
              {name}
            </h3>
            <BurstTable caption={name} own={null} pair={pair} />
            <Source pair={pair} />
          </section>
        );
      })}
    </details>
  );
}

type Cell =
  | {
      readonly kind: 'verdict';
      readonly verdict: 'ALLOW' | 'CHALLENGE' | 'ESCALATE' | 'BLOCK';
      /** The decision applied from the next request (an asynchronous decision): this request itself went through. */
      readonly later?: boolean;
    }
  | { readonly kind: 'word'; readonly key: string };

/**
 * The repeated read (옛 M-stack): the same customer lookup five times. The normal work is the visitor's own run (sent
 * live here) or the measurement's stored real run; the attack is always the measurement's stored real run. Each cell
 * is Contexa's own decision of that request, or what the request met without one (an earlier decision).
 */
function RepeatTab() {
  const { t } = useTranslation();
  const options = useLabOptions();
  const steps = options.data?.cases.find((labCase) => labCase.key === WORK)?.requests.length ?? 5;
  const attackSteps = options.data?.cases.find((labCase) => labCase.key === ATTACK)?.requests.length ?? 5;
  const runs = useGroupRuns([WORK]);
  const tried = useAgentTry(WORK);
  const view = tried.live;
  const active = view !== null && ACTIVE.has(view.status);
  const ownRun = !active ? tried.runId : null;
  const workMeasured = useMeasuredCase(ownRun ? null : WORK).data?.middleRun ?? null;
  const attackMeasured = useMeasuredCase(ATTACK).data?.middleRun ?? null;
  const { send, sending, ready, refusal, waiting, turnstileContainer, turnstileRequired } = useLiveSend(WORK, () => undefined);
  const why = !runs.visitorReady
    ? t('ux.review.reason.visitor')
    : active
      ? t('ux.surge.reason.active')
      : turnstileRequired && !ready && !sending && !waiting
        ? t('ux.review.reason.human')
        : undefined;
  return (
    <>
      <p className={[styles.sectionDesc, styles.repeatDesc].join(' ')}>{t('ux.surge.repeat.desc')}</p>
      {view?.status === 'QUEUED' ? (
        <Note icon="hourglass">
          {t('ux.live.queued', { position: view.queuePosition })}
          {view.queueWaitSeconds !== null ? ` ${t('ux.live.queuedWait', { seconds: view.queueWaitSeconds })}` : ''}
        </Note>
      ) : null}
      {view !== null && ENDED.has(view.status) ? <Note tone="warn">{t('ux.live.failed')}</Note> : null}
      <div className={styles.section}>
        <RepeatLane
          title={t('ux.surge.repeat.work')}
          runId={ownRun ?? workMeasured}
          own={ownRun !== null}
          live={active ? view : null}
          steps={steps}
        />
        <RepeatLane title={t('ux.surge.repeat.attack')} runId={attackMeasured} own={false} live={null} steps={attackSteps} />
      </div>
      {turnstileRequired ? <div ref={turnstileContainer} className={review.turnstile} /> : null}
      <div className={styles.repeatRun}>
        <Button
          variant="primary"
          size="lg"
          icon="repeat"
          busy={sending || waiting}
          {...(why ? { disabledReason: why } : {})}
          onClick={() => void send()}
        >
          {t('ux.surge.repeat.send')}
        </Button>
      </div>
      {refusal ? <Note tone="warn">{t(`ux.review.refusal.${refusal}`)}</Note> : null}
    </>
  );
}

function RepeatLane({
  title,
  runId,
  own,
  live,
  steps,
}: {
  readonly title: string;
  readonly runId: string | null;
  readonly own: boolean;
  readonly live: LiveRunView | null;
  readonly steps: number;
}) {
  const { t, i18n } = useTranslation();
  const anatomies = useAnatomies(live ? null : runId, steps);
  const results = useRunStepResults(live ? null : runId, steps);
  const cells: Cell[] = Array.from({ length: steps }, (_, index) => {
    if (live) {
      const cell = agentCell(live.steps.find((step) => step.stepNo === index + 1)?.layers.D ?? null);
      return cell === null || cell === 'PENDING' || cell === 'NONE' || cell === 'CONFIRM'
        ? { kind: 'word', key: 'ux.surge.repeat.waiting' }
        : { kind: 'verdict', verdict: cell };
    }
    const verdict = verdictOf(anatomies[index]?.data);
    if (verdict && verdict !== 'PENDING' && verdict !== 'NONE') {
      const timing = results[index]?.layers.find((layer) => layer.control === 'D')?.evidence.timing;
      return { kind: 'verdict', verdict, later: verdict !== 'ALLOW' && timing === 'NEXT_REQUEST' };
    }
    return priorOf(results[index])
      ? { kind: 'word', key: 'ux.lanes.prior' }
      : { kind: 'word', key: 'ux.surge.repeat.none' };
  });
  const last = [...anatomies].reverse().find((query) => query.data !== undefined)?.data;
  const before = last?.figures?.baselineBefore ?? null;
  const after = last?.figures?.baselineAfter ?? null;
  const n = (value: number) => formatNumber(value, i18n.language);
  return (
    <section className={styles.cellsRow} aria-label={title}>
      <p className={styles.cellsHead}>
        {title}
        {runId ? (
          <>
            <Badge tone="line">{own ? t('ux.surge.repeat.own') : t('ux.surge.repeat.stored')}</Badge>
            <Link to={`/runs/${encodeURIComponent(runId)}`}>
              <CodeChip value={runId} />
            </Link>
          </>
        ) : null}
      </p>
      <ol className={styles.cells}>
        {cells.map((cell, index) => (
          <li key={index}>
            <span className={styles.requestNo}>{t('ux.pick.requestNo', { n: index + 1 })}</span>
            {cell.kind === 'verdict' ? (
              <>
                <VerdictBadge verdict={cell.verdict} />
                {cell.later ? <span className={styles.counterNote}>{t('ux.surge.repeat.later')}</span> : null}
              </>
            ) : (
              <span className={styles.wait}>{t(cell.key)}</span>
            )}
          </li>
        ))}
      </ol>
      {before !== null && after !== null ? (
        <p className={styles.counterNote}>
          {t(before === after ? 'ux.surge.repeat.learnedSame' : 'ux.surge.repeat.learned', {
            from: n(before),
            to: n(after),
          })}
        </p>
      ) : null}
    </section>
  );
}
