import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useAgentSubject } from '../../api/agentCase';
import { useBurstSnapshots, type AgentSnapshot, type BurstCase } from '../../api/agentSnapshots';
import { MainScreen } from '../../components/main/MainScreen';
import { SnapshotBadge } from '../../components/main/SnapshotBadge';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { Fold } from '../../components/main/Fold';
import { count } from '../../journey/format';
import { AGENT_PATHS, layersOf } from './agentGroup';
import { AgentTimeline } from './AgentTimeline';
import { BURST_ROWS, firstStop } from './burstRows';
import { BurstLive } from './BurstLive';
import styles from './AgentBurstPage.module.css';

/**
 * 6-6, many requests at once (docs/agent Agent중심-화면 AS-10, AC-7a): the three bursts the portal measured, each as two
 * stored real runs: control D's decision flights off (every request analysed on its own) and on (identical requests
 * joined to one analysis, the number at once limited). Every count is the portal's, made from the stored run; the
 * visitor starts nothing and no model is called. The first burst's requests can be read one by one, folded as bursts.
 */
export default function AgentBurstPage() {
  const { t } = useTranslation();
  const subject = useAgentSubject();
  const { pending, bursts: ready } = useBurstSnapshots();

  return (
    <MainScreen title={t('main.6-6.title')} intro={t('main.6-6.intro')} subject={subject}>
      {/* AS-13: a burst of up to ten requests the visitor sends live, above the measured ones */}
      <BurstLive />
      {pending ? <StateScreen kind="loading" /> : null}
      {!pending && ready.length === 0 ? (
        <p className={styles.note}>
          <Link to={AGENT_PATHS.reason}>{t('main.6-5.toReason')}</Link>
        </p>
      ) : null}
      {!pending && ready.length > 0 ? (
        <div className={styles.stack} id="burst-measured">
          {ready.slice(0, 1).map((entry) => (
            <Burst key={entry.burst} burst={entry.burst} off={entry.off} on={entry.on} timeline />
          ))}
          {/* AC-N9: the first burst is the view; the others wait under one line, so a phone is not made to scroll past all. */}
          {ready.length > 1 ? (
            <Fold name="burst-others" summary={t('main.6-6.othersFold', { count: ready.length - 1 })}>
              {ready.slice(1).map((entry) => (
                <Burst key={entry.burst} burst={entry.burst} off={entry.off} on={entry.on} timeline={false} />
              ))}
            </Fold>
          ) : null}
          <p className={styles.note}>{t('main.6-6.limit')}</p>
        </div>
      ) : null}
    </MainScreen>
  );
}

function Burst({
  burst,
  off,
  on,
  timeline,
}: {
  readonly burst: BurstCase;
  readonly off: AgentSnapshot;
  readonly on: AgentSnapshot;
  readonly timeline: boolean;
}) {
  const { t, i18n } = useTranslation();
  return (
    <section className={styles.burst} aria-labelledby={`burst-${burst}`}>
      <h2 id={`burst-${burst}`} className={styles.heading}>
        {t(`main.6-6.case.${burst}`)}
      </h2>
      <p className={styles.explain}>{t(`main.6-6.explain.${burst}`)}</p>
      {/* AC-N2: what the burst shows is the view; its marks, the numbers of the two states and the timeline wait under one line. */}
      <Fold name="burst-record" summary={t('main.6-6.recordFold')}>
        <p className={styles.badges}>
          {/* AC-7a: the requests of this size are a stored measurement, not a run made for the visitor. */}
          <SourceBadge
            kind="repeated"
            label={t('main.6-6.measured', { requests: count(on.summary.requests, i18n.language) })}
          />
          <SnapshotBadge snapshot={on} />
        </p>
        <table className={styles.table}>
          <caption className="visually-hidden">{t(`main.6-6.case.${burst}`)}</caption>
          <thead>
            <tr>
              <th scope="col" />
              <th scope="col">{t('main.6-6.off')}</th>
              <th scope="col">{t('main.6-6.on')}</th>
            </tr>
          </thead>
          <tbody>
            {BURST_ROWS.map((row) => (
              <tr key={row}>
                <th scope="row">{t(`main.6-6.row.${row}`)}</th>
                <td>{count(off.summary[row], i18n.language)}</td>
                <td>{count(on.summary[row], i18n.language)}</td>
              </tr>
            ))}
            <tr>
              <th scope="row">{t('main.6-6.row.firstStopStep')}</th>
              <td>{firstStop(t, off.summary)}</td>
              <td>{firstStop(t, on.summary)}</td>
            </tr>
          </tbody>
        </table>
        {timeline ? (
          <details className={styles.details}>
            <summary>{t('main.6-6.timeline')}</summary>
            <AgentTimeline
              rows={on.run.steps.map((step) => ({ stepNo: step.stepNo, layers: layersOf(step), step }))}
            />
          </details>
        ) : null}
      </Fold>
    </section>
  );
}
