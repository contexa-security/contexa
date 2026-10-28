import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAgentRun, useAgentTry, type BurstSummary } from '../../api/agentCase';
import { postJson } from '../../api/http';
import { useLiveConfig } from '../../api/queries';
import type { LiveBurst, LiveRunView } from '../../api/types';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { Fold } from '../../components/main/Fold';
import { useLiveSend } from '../../hooks/useLiveSend';
import { count } from '../../journey/format';
import { ChoiceGroup } from '../lab/ChoiceGroup';
import { AGENT_PATHS } from './agentGroup';
import { BURST_ROWS, firstStop } from './burstRows';
import styles from './AgentBurstPage.module.css';

/** The numbers a visitor may pick for a live burst, never above what the portal allows. */
const PRESETS = [1, 3, 5, 10] as const;

/** The run is still going, or waits for the visitor. */
const ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED', 'CONFIRMING']);
const FAILED = new Set(['FAILED', 'EXPIRED']);

/** The numbers offered: the presets below the most, then the most itself. */
function numbersOf(most: number): readonly number[] {
  return [...PRESETS.filter((number) => number < most), most];
}

/**
 * The burst a visitor sends live on 6-6 (docs/agent Agent중심-화면 AS-13, AC-7b): the same list request, a few at once, up
 * to the most the portal allows. The visitor picks the number, sends it through the portal's gate, stays on the screen
 * while it runs, and reads the counts the portal made of their own run in the rows of the stored measurements. Nothing
 * shows while the portal offers no burst.
 */
export function BurstLive() {
  const burst = useLiveConfig().data?.burst;
  return burst ? <BurstSend burst={burst} /> : null;
}

function BurstSend({ burst }: { readonly burst: LiveBurst }) {
  const { t, i18n } = useTranslation();
  const config = useLiveConfig().data;
  const numbers = numbersOf(burst.most);
  const [picked, setPicked] = useState<number>(burst.most);
  const { send, sending, ready, refusal, waiting, turnstileContainer, turnstileRequired } = useLiveSend(
    burst.case,
    () => undefined,
    {
      post: (turnstileToken) =>
        postJson<LiveRunView & { reason?: string }>('/api/live/runs', {
          scenario: burst.case,
          turnstileToken,
          copies: picked,
        }),
    },
  );
  const tried = useAgentTry(burst.case);
  const status = tried.live?.status ?? null;
  const active = status !== null && ACTIVE.has(status);
  const failed = status !== null && FAILED.has(status);
  const finished = !active && !failed && tried.runId !== null;
  const run = useAgentRun(finished ? tried.runId : null);
  const own = run.data?.burst ?? null;
  const tickets = config?.liveTicketsLeft;
  const noShare = tickets !== undefined && tickets <= 0;
  const runsLeft = config?.remainingAgentToday;
  const noPoints = config !== undefined && config.remainingToday < burst.points;
  const cannot = noShare || noPoints;

  return (
    <>
      {/* AC-N2: the measured bursts are the view; the visitor's own send waits under one line and opens when it runs. */}
      <Fold name="burst-live" summary={t('main.6-6.live.title')} open={active || sending || finished}>
        <section className={styles.burst} aria-labelledby="burst-live">
          <h2 id="burst-live" className="visually-hidden">
            {t('main.6-6.live.title')}
          </h2>
          <p className={styles.explain}>
            {t('main.6-6.live.intro', { most: count(burst.most, i18n.language) })}
          </p>
          <ChoiceGroup
            name="burst-copies"
            label={t('main.6-6.live.count')}
            value={picked}
            onChange={setPicked}
            choices={numbers.map((number) => ({
              value: number,
              label: t('main.6-6.live.countValue', { n: count(number, i18n.language) }),
            }))}
          />
          {runsLeft === undefined ? null : (
            <p className={styles.explain}>
              {t('main.6-6.live.cost', { points: burst.points, runs: count(runsLeft, i18n.language) })}
            </p>
          )}
          <button
            type="button"
            className={styles.send}
            disabled={!ready || active || cannot}
            onClick={() => void send()}
          >
            {sending || active
              ? t('main.6-6.live.sending')
              : t('main.6-6.live.send', { n: count(picked, i18n.language) })}
          </button>
          {cannot ? (
            <p className={styles.explain}>
              {noShare ? t('main.6-6.live.noTickets') : t('main.6-6.live.noPoints', { points: burst.points })}{' '}
              <a href="#burst-measured">{t('main.6-6.live.toMeasured')}</a>
            </p>
          ) : null}
          {active ? <p className={styles.explain}>{t('main.6-6.live.running')}</p> : null}
          {failed ? <p className={styles.explain}>{t('main.6-6.live.failed')}</p> : null}
          {turnstileRequired ? <div ref={turnstileContainer} /> : null}
          {waiting ? <p className={styles.explain}>{t('p1.predict.waitEarlier')}</p> : null}
          {refusal ? (
            <StateScreen
              kind={refusal === 'dailyLimit' ? 'dailyLimit' : refusal === 'paused' ? 'paused' : 'outage'}
              recordTo={AGENT_PATHS.burst}
            />
          ) : null}
        </section>
      </Fold>
      {own && tried.runId ? <OwnBurst summary={own} runId={tried.runId} /> : null}
    </>
  );
}

/** The counts of the visitor's own burst, in the rows of the stored measurements. */
function OwnBurst({ summary, runId }: { readonly summary: BurstSummary; readonly runId: string }) {
  const { t, i18n } = useTranslation();
  return (
    <section className={styles.burst} aria-labelledby="burst-own">
      <h2 id="burst-own" className={styles.heading}>
        {t('main.6-6.own.title')}
      </h2>
      <p className={styles.badges}>
        <SourceBadge kind="run" runId={runId} />
      </p>
      <table className={styles.table}>
        <caption className="visually-hidden">{t('main.6-6.own.title')}</caption>
        <thead>
          <tr>
            <th scope="col" />
            <th scope="col">{t('main.6-6.own.column')}</th>
          </tr>
        </thead>
        <tbody>
          {BURST_ROWS.map((row) => (
            <tr key={row}>
              <th scope="row">{t(`main.6-6.row.${row}`)}</th>
              <td>{count(summary[row], i18n.language)}</td>
            </tr>
          ))}
          <tr>
            <th scope="row">{t('main.6-6.row.firstStopStep')}</th>
            <td>{firstStop(t, summary)}</td>
          </tr>
        </tbody>
      </table>
      <p className={styles.explain}>{t('main.6-6.own.note')}</p>
    </section>
  );
}
