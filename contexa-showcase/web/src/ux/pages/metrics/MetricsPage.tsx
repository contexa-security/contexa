import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { useStats } from '../../../api/queries';
import type { StatsView } from '../../../api/types';
import { formatNumber, formatSeconds, formatUtc } from '../../format';
import {
  Bar,
  Card,
  CodeChip,
  DataTable,
  ErrorState,
  KeyValue,
  Kpi,
  Loading,
  Note,
  PageHead,
  StackedBar,
  TabPanel,
  Tabs,
  VerdictBadge,
  type Segment,
} from '../../ui';
import { UX_VERDICTS } from '../../verdict';
import styles from './Metrics.module.css';
import { ACTIONS, axisEnd, decisionsOf, failedShare, operatorRuns, type Action } from './stats';

const TABS = ['overview', 'decisions', 'latency', 'runs', 'agreement'] as const;
type TabId = (typeof TABS)[number];

/**
 * Operational metrics (기획안 7.4, DEC-63): the operations record of the demo's real decisions from `/api/stats` only —
 * the decisions, their latency, the runs and the repeated-decision agreement. The effect (misses, false positives) is
 * the validation menu's; a trend by day is not in the answer and is not drawn (D-8).
 */
export default function MetricsPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const asked = params.get('tab') as TabId | null;
  const tab: TabId = asked && TABS.includes(asked) ? asked : 'overview';
  const stats = useStats();
  return (
    <>
      <PageHead
        title={t('ux.metrics.title')}
        desc={t('ux.metrics.desc')}
        {...(stats.data ? { status: <Period stats={stats.data} /> } : {})}
      />
      <Tabs
        idBase="metrics"
        label={t('ux.metrics.tabs')}
        value={tab}
        onChange={(id) => setParams(new URLSearchParams({ tab: id }), { replace: true })}
        items={TABS.map((id) => ({ id, label: t(`ux.metrics.tab.${id}`) }))}
      />
      <TabPanel idBase="metrics" id={tab}>
        {stats.isPending ? (
          <Loading rows={6} />
        ) : stats.isError ? (
          <ErrorState onRetry={() => void stats.refetch()} />
        ) : tab === 'overview' ? (
          <Overview stats={stats.data} />
        ) : tab === 'decisions' ? (
          <Decisions stats={stats.data} />
        ) : tab === 'latency' ? (
          <Latency stats={stats.data} />
        ) : tab === 'runs' ? (
          <Runs stats={stats.data} />
        ) : (
          <Agreement stats={stats.data} />
        )}
      </TabPanel>
    </>
  );
}

/** The period of the counted runs (UTC dates) and when the portal computed the figures. */
function Period({ stats }: { readonly stats: StatsView }) {
  const { t } = useTranslation();
  const zone = t('ux.time.zone');
  return (
    <span className={styles.period}>
      {stats.runs.firstAt && stats.runs.lastAt ? (
        <span>
          {t('ux.metrics.period', {
            from: stats.runs.firstAt.slice(0, 10),
            to: stats.runs.lastAt.slice(0, 10),
            zone,
          })}
        </span>
      ) : null}
      <span>{t('ux.metrics.computed', { time: formatUtc(stats.computedAt), zone })}</span>
    </span>
  );
}

function useFormat() {
  const { i18n } = useTranslation();
  return {
    n: (value: number) => formatNumber(value, i18n.language),
    percent: (share: number) => formatNumber(share * 100, i18n.language, 1),
    seconds: (milliseconds: number) => formatSeconds(milliseconds, i18n.language),
  };
}

function Overview({ stats }: { readonly stats: StatsView }) {
  const { t } = useTranslation();
  const { n, percent, seconds } = useFormat();
  const decisions = decisionsOf(stats);
  const share = failedShare(stats.runs);
  const { p50Ms, p95Ms } = stats.decisionTime;
  return (
    <div className={styles.stack}>
      <div className={styles.kpis}>
        <Kpi
          icon="gavel"
          label={t('ux.metrics.kpi.decisions')}
          value={n(decisions)}
          unit={t('ux.metrics.unit.decisions')}
          foot={t('ux.metrics.kpi.decisionsFoot', { runs: n(stats.runs.completed) })}
        />
        <Kpi
          icon="timer"
          label={t('ux.metrics.kpi.latency')}
          value={p50Ms === null ? '—' : seconds(p50Ms)}
          {...(p50Ms === null ? {} : { unit: t('ux.metrics.unit.seconds') })}
          foot={p95Ms === null ? t('ux.metrics.noLatency') : t('ux.metrics.kpi.latencyFoot', { p95: seconds(p95Ms) })}
        />
        <Kpi
          icon="play"
          label={t('ux.metrics.kpi.runs')}
          value={n(stats.runs.completed)}
          unit={t('ux.metrics.unit.runs')}
          foot={t('ux.metrics.kpi.runsFoot', {
            failed: n(stats.runs.failed),
            share: share === null ? '—' : percent(share),
          })}
        />
        <Kpi
          icon="users"
          label={t('ux.metrics.kpi.live')}
          value={n(stats.runs.live)}
          unit={t('ux.metrics.unit.runs')}
          foot={t('ux.metrics.kpi.liveFoot', { operator: n(operatorRuns(stats.runs)) })}
        />
      </div>
      <p className={styles.note}>{t('ux.metrics.counted')}</p>
      <div className={styles.split}>
        <Card title={t('ux.metrics.mix.title')} sub={t('ux.metrics.mix.sub', { n: n(decisions) })}>
          <Mix stats={stats} />
        </Card>
        <Card
          title={t('ux.metrics.latency.title')}
          sub={t('ux.metrics.latency.sub', { n: n(stats.decisionTime.decisions) })}
        >
          <LatencyStrip stats={stats} />
        </Card>
      </div>
      <div className={styles.split}>
        <Uncounted stats={stats} />
        <Settings stats={stats} />
      </div>
    </div>
  );
}

function Mix({ stats }: { readonly stats: StatsView }) {
  const { t } = useTranslation();
  const { n } = useFormat();
  if (decisionsOf(stats) === 0) {
    return <p className={styles.line}>{t('ux.metrics.noDecision')}</p>;
  }
  const segments: Segment[] = ACTIONS.map((action) => ({
    label: t(UX_VERDICTS[action].labelKey),
    value: stats.engineActions[action] ?? 0,
    tone: UX_VERDICTS[action].tone,
  }));
  return <StackedBar label={t('ux.metrics.mix.title')} segments={segments} format={n} />;
}

/** The median and the 95th percentile on one axis from zero, the axis ending at the p95 rounded up to five seconds. */
function LatencyStrip({ stats }: { readonly stats: StatsView }) {
  const { t } = useTranslation();
  const { seconds, n } = useFormat();
  const { p50Ms, p95Ms } = stats.decisionTime;
  if (p50Ms === null || p95Ms === null) {
    return <p className={styles.line}>{t('ux.metrics.noLatency')}</p>;
  }
  const end = axisEnd(p95Ms);
  const share = (milliseconds: number) => Math.min(1, milliseconds / (end * 1000));
  const at = (milliseconds: number) => `${share(milliseconds) * 100}%`;
  // A mark near an end of the axis is aligned to that end, so its words stay inside the card.
  const edge = (milliseconds: number) =>
    share(milliseconds) < 0.12 ? 'start' : share(milliseconds) > 0.88 ? 'end' : undefined;
  const ticks = Array.from({ length: end / 5 + 1 }, (_, index) => index * 5);
  return (
    <div
      className={styles.latency}
      role="img"
      aria-label={t('ux.metrics.latency.axis', { p50: seconds(p50Ms), p95: seconds(p95Ms), max: n(end) })}
    >
      <div className={styles.markRow} aria-hidden="true">
        <span className={styles.mark} data-edge={edge(p50Ms)} style={{ insetInlineStart: at(p50Ms) }}>
          p50 {seconds(p50Ms)}
        </span>
      </div>
      <div className={styles.track} aria-hidden="true">
        <span className={styles.range} style={{ insetInlineStart: at(p50Ms), insetInlineEnd: `${(1 - share(p95Ms)) * 100}%` }} />
      </div>
      <div className={styles.markRow} aria-hidden="true">
        <span className={styles.mark} data-edge={edge(p95Ms)} style={{ insetInlineStart: at(p95Ms) }}>
          p95 {seconds(p95Ms)}
        </span>
      </div>
      <div className={styles.axis} aria-hidden="true">
        {ticks.map((tick) => (
          <span key={tick}>{t('ux.metrics.latency.tick', { value: n(tick) })}</span>
        ))}
      </div>
    </div>
  );
}

/** Named figures with their definitions: the name and the figure on one line, the definition under them across the card. */
function Defined({
  rows,
}: {
  readonly rows: readonly { readonly name: string; readonly value: string; readonly def: string }[];
}) {
  return (
    <dl className={styles.defined}>
      {rows.map((row) => (
        <div key={row.name} className={styles.definedRow}>
          <dt>{row.name}</dt>
          <dd className={styles.definedValue}>{row.value}</dd>
          <dd className={styles.definedDef}>{row.def}</dd>
        </div>
      ))}
    </dl>
  );
}

function Uncounted({ stats }: { readonly stats: StatsView }) {
  const { t } = useTranslation();
  const { n } = useFormat();
  return (
    <Card title={t('ux.metrics.uncounted.title')} sub={t('ux.metrics.uncounted.sub')}>
      <Defined
        rows={[
          {
            name: t('ux.metrics.uncounted.reused'),
            value: n(stats.unresolved.noNewAnalysis),
            def: t('ux.metrics.uncounted.reusedDef'),
          },
          {
            name: t('ux.metrics.uncounted.technical'),
            value: n(stats.unresolved.technical),
            def: t('ux.metrics.uncounted.technicalDef'),
          },
        ]}
      />
    </Card>
  );
}

/** The engine mode as code and in words; a mode the dictionary does not name stays as code only. */
function Mode({ mode }: { readonly mode: string }) {
  const { t, i18n } = useTranslation();
  const key = `ux.metrics.mode.${mode}`;
  return (
    <span className={styles.mode}>
      <CodeChip value={mode} />
      {i18n.exists(key) ? <span>{t(key)}</span> : null}
    </span>
  );
}

function Settings({ stats }: { readonly stats: StatsView }) {
  const { t } = useTranslation();
  const { n } = useFormat();
  return (
    <Card title={t('ux.metrics.settings.title')} sub={t('ux.metrics.settings.sub')}>
      {stats.spec === null ? (
        <p className={styles.line}>{t('ux.metrics.settings.none')}</p>
      ) : (
        <KeyValue
          alignEnd
          items={[
            { label: t('ux.metrics.settings.mode'), value: <Mode mode={stats.spec.effectiveMode} /> },
            { label: t('ux.metrics.settings.specs'), value: t('ux.metrics.settings.specsValue', { n: n(stats.specCount) }) },
            {
              label: t('ux.metrics.settings.agreement'),
              value: t('ux.metrics.settings.agreementValue', {
                k: n(stats.agreement.agreeing),
                n: n(stats.agreement.repetitions),
              }),
            },
            { label: t('ux.metrics.settings.zone'), value: <CodeChip value={stats.spec.timeZone} /> },
          ]}
        />
      )}
    </Card>
  );
}

function Decisions({ stats }: { readonly stats: StatsView }) {
  const { t } = useTranslation();
  const { n, percent } = useFormat();
  const decisions = decisionsOf(stats);
  const hold = stats.engineActions.ESCALATE ?? 0;
  return (
    <div className={styles.stack}>
      <Card title={t('ux.metrics.decisions.title')} sub={t('ux.metrics.decisions.sub', { n: n(decisions) })} flush>
        {decisions === 0 ? (
          <p className={[styles.line, styles.padded].join(' ')}>{t('ux.metrics.noDecision')}</p>
        ) : (
          <DataTable<Action>
            caption={t('ux.metrics.decisions.title')}
            rowKey={(action) => action}
            rows={ACTIONS}
            columns={[
              { key: 'decision', header: t('ux.metrics.col.decision'), render: (action) => <VerdictBadge verdict={action} /> },
              {
                key: 'count',
                header: t('ux.metrics.col.count'),
                numeric: true,
                render: (action) => n(stats.engineActions[action] ?? 0),
              },
              {
                key: 'share',
                header: t('ux.metrics.col.share'),
                render: (action) => {
                  const share = (stats.engineActions[action] ?? 0) / decisions;
                  return (
                    <span className={styles.shareCell}>
                      <Bar label={t(UX_VERDICTS[action].labelKey)} value={share} tone={UX_VERDICTS[action].tone} />
                      <span className={styles.figure}>{t('ux.metrics.share', { value: percent(share) })}</span>
                    </span>
                  );
                },
              },
            ]}
          />
        )}
      </Card>
      <div className={styles.split}>
        <Card title={t('ux.metrics.after.title')} sub={t('ux.metrics.after.sub')}>
          <Defined
            rows={[
              {
                name: t('ux.metrics.after.held'),
                value: t('ux.metrics.after.heldValue', { n: n(stats.escalateHeld), total: n(hold) }),
                def: t('ux.metrics.after.heldDef'),
              },
              {
                name: t('ux.metrics.after.expired'),
                value: t('ux.metrics.count', { n: n(stats.blockedAfterReview) }),
                def: t('ux.metrics.after.expiredDef'),
              },
              {
                name: t('ux.metrics.after.released'),
                value: t('ux.metrics.count', { n: n(stats.releases) }),
                def: t('ux.metrics.after.releasedDef'),
              },
            ]}
          />
        </Card>
        <Uncounted stats={stats} />
      </div>
    </div>
  );
}

function Latency({ stats }: { readonly stats: StatsView }) {
  const { t } = useTranslation();
  const { n, seconds } = useFormat();
  const { p50Ms, p95Ms } = stats.decisionTime;
  return (
    <div className={styles.split}>
      <Card
        title={t('ux.metrics.latency.title')}
        sub={t('ux.metrics.latency.sub', { n: n(stats.decisionTime.decisions) })}
      >
        <div className={styles.stack}>
          <LatencyStrip stats={stats} />
          <KeyValue
            alignEnd
            items={[
              { label: 'p50', value: p50Ms === null ? '—' : t('ux.time.seconds', { value: seconds(p50Ms) }) },
              { label: 'p95', value: p95Ms === null ? '—' : t('ux.time.seconds', { value: seconds(p95Ms) }) },
              { label: t('ux.metrics.latency.counted'), value: t('ux.metrics.count', { n: n(stats.decisionTime.decisions) }) },
              { label: t('ux.metrics.latency.span'), value: t('ux.metrics.latency.spanValue') },
            ]}
          />
        </div>
      </Card>
      <Card title={t('ux.metrics.timing.title')}>
        <div className={styles.stack}>
          <p className={styles.line}>{t('ux.metrics.timing.sync')}</p>
          <p className={styles.line}>{t('ux.metrics.timing.async')}</p>
          <Link className={styles.textLink} to="/engine?tab=flow">
            {t('ux.metrics.timing.link')}
          </Link>
        </div>
      </Card>
    </div>
  );
}

function Runs({ stats }: { readonly stats: StatsView }) {
  const { t } = useTranslation();
  const { n, percent } = useFormat();
  const share = failedShare(stats.runs);
  const count = (value: number) => t('ux.metrics.runs.countValue', { n: n(value) });
  const zone = t('ux.time.zone');
  return (
    <div className={styles.split}>
      <Card title={t('ux.metrics.runs.title')} sub={t('ux.metrics.runs.sub')}>
        <KeyValue
          alignEnd
          items={[
            { label: t('ux.metrics.runs.completed'), value: count(stats.runs.completed) },
            {
              label: t('ux.metrics.runs.failed'),
              value: t('ux.metrics.runs.failedValue', {
                n: n(stats.runs.failed),
                share: share === null ? '—' : percent(share),
              }),
            },
            { label: t('ux.metrics.runs.live'), value: count(stats.runs.live) },
            { label: t('ux.metrics.runs.operator'), value: count(operatorRuns(stats.runs)) },
            { label: t('ux.metrics.runs.today'), value: count(stats.runs.today) },
            {
              label: t('ux.metrics.runs.first'),
              value: stats.runs.firstAt ? `${formatUtc(stats.runs.firstAt)} ${zone}` : '—',
            },
            {
              label: t('ux.metrics.runs.last'),
              value: stats.runs.lastAt ? `${formatUtc(stats.runs.lastAt)} ${zone}` : '—',
            },
          ]}
        />
      </Card>
      <Card title={t('ux.metrics.scope.title')} sub={t('ux.metrics.scope.sub')}>
        <div className={styles.stack}>
          <KeyValue
            alignEnd
            items={[
              { label: t('ux.metrics.scope.threat'), value: count(stats.scope.threatRuns) },
              { label: t('ux.metrics.scope.normal'), value: count(stats.scope.normalRuns) },
              { label: t('ux.metrics.scope.other'), value: count(stats.scope.otherRuns) },
            ]}
          />
          <Note icon="info">
            {t('ux.metrics.scope.effect')}{' '}
            <Link className={styles.textLink} to="/validation">
              {t('ux.menu.validation')}
            </Link>
          </Note>
        </div>
      </Card>
    </div>
  );
}

/** A recording's scene in words: the threat run or the normal-work run of the pair. */
function sceneKey(scene: string): string | null {
  return scene === 'ATTACK' ? 'ux.metrics.scope.threat' : scene === 'LEGITIMATE' ? 'ux.metrics.scope.normal' : null;
}

function Agreement({ stats }: { readonly stats: StatsView }) {
  const { t } = useTranslation();
  const { n } = useFormat();
  const recordings = stats.agreement.recordings;
  return (
    <Card
      title={t('ux.metrics.agreement.title')}
      sub={t('ux.metrics.agreement.sub')}
      actions={
        recordings.length > 0 ? (
          <span className={styles.figure}>
            {t('ux.metrics.agreement.total', { k: n(stats.agreement.agreeing), n: n(stats.agreement.repetitions) })}
          </span>
        ) : undefined
      }
      flush
    >
      {recordings.length === 0 ? (
        <p className={[styles.line, styles.padded].join(' ')}>{t('ux.metrics.agreement.none')}</p>
      ) : (
        <DataTable
          caption={t('ux.metrics.agreement.title')}
          stack
          rowKey={(row) => `${row.pairKey}-${row.scene}`}
          rows={recordings}
          columns={[
            { key: 'recording', header: t('ux.metrics.col.recording'), strong: true, render: (row) => <CodeChip value={row.pairKey} /> },
            {
              key: 'scene',
              header: t('ux.metrics.col.scene'),
              render: (row) => {
                const key = sceneKey(row.scene);
                return key ? t(key) : <CodeChip value={row.scene} />;
              },
            },
            {
              key: 'agree',
              header: t('ux.metrics.col.agree'),
              numeric: true,
              render: (row) => t('ux.metrics.agreement.value', { k: n(row.agreeing), n: n(row.repetitions) }),
            },
            {
              key: 'recorded',
              header: t('ux.metrics.col.recorded'),
              numeric: true,
              render: (row) => `${formatUtc(row.recordedAt)} ${t('ux.time.zone')}`,
            },
          ]}
        />
      )}
    </Card>
  );
}
