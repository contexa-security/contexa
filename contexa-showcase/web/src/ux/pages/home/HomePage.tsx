import { useTranslation } from 'react-i18next';
import { useAnatomy, useReceived } from '../../../api/anatomy';
import { useHook, type HookColumn } from '../../../api/hook';
import { HttpError } from '../../../api/http';
import { useLabOptions } from '../../../api/lab';
import { useLiveConfig, useStats } from '../../../api/queries';
import { CONTROL_ORDER } from '../../../domain/verdict';
import { formatNumber, formatSeconds, formatUtc, localTime } from '../../format';
import { ControlLanes, type LaneRow } from '../../simulate/ControlLanes';
import { EXISTING, companyClock, controlVerdict, deviceWords, flowPath } from '../../simulate/person';
import { ButtonLink, CodeChip, EmptyState, ErrorState, Icon, Loading } from '../../ui';
import { BenchBand, HowBand, ScenarioCard } from './HomeParts';
import styles from './Home.module.css';

/**
 * The start of the demo (기획안 7.0 d-home, F-1 · F-2): a real recorded decision understood without a click, the
 * account-takeover run one click away, the four threat scenarios and the four steps every run walks. Every number is
 * read from the portal: the published recorded run (/api/hook, DEC-17), the latency (/api/stats) and the daily runs
 * (/api/live/config, DEC-20).
 */
export default function HomePage() {
  const { t, i18n } = useTranslation();
  const stats = useStats();
  const live = useLiveConfig();
  const options = useLabOptions();
  const p50 = stats.data?.decisionTime.p50Ms ?? null;
  const stepsOf = (key: string) => options.data?.cases.find((labCase) => labCase.key === key)?.steps ?? null;
  const atoSteps = stepsOf('S13');
  const insiderSteps = stepsOf('S16');
  const agentCases = live.data?.agentCases?.length ?? null;
  const burst = live.data?.burst ?? null;
  const n = (value: number) => formatNumber(value, i18n.language);
  return (
    <>
      <section className={styles.hero} aria-labelledby="home-title">
        <div className={styles.heroText}>
          <span className={styles.liveTag}>
            <span className={styles.liveDot} aria-hidden="true" />
            {t('ux.home.live')}
          </span>
          <h1 id="home-title" tabIndex={-1} className={styles.heroTitle}>
            {t('ux.home.title.line1')}
            <br />
            {t('ux.home.title.line2')}
          </h1>
          <p className={styles.heroDesc}>{t('ux.home.desc')}</p>
          <div className={styles.heroActions}>
            <ButtonLink to={flowPath('S13', 'review')} variant="primary" size="lg" icon="play">
              {t('ux.home.run')}
            </ButtonLink>
            <ButtonLink to="/simulate/person" size="lg" icon="layout-grid">
              {t('ux.home.choose')}
            </ButtonLink>
          </div>
          <ul className={styles.heroMeta}>
            <li>
              <Icon name="check" size="sm" />
              {t('ux.home.meta.noSignup')}
            </li>
            {p50 !== null ? (
              <li>
                <Icon name="check" size="sm" />
                {t('ux.home.meta.latency', { p50: formatSeconds(p50, i18n.language) })}
              </li>
            ) : null}
            {live.data ? (
              <li>
                <Icon name="check" size="sm" />
                {t('ux.home.meta.daily', { n: n(live.data.dailyRuns) })}
              </li>
            ) : null}
          </ul>
        </div>
        <RecordedRun />
      </section>

      <section aria-labelledby="scenarios-title">
        <div className={styles.sectionHead}>
          <div>
            <h2 id="scenarios-title" className={styles.sectionTitle}>
              {t('ux.home.scenarios.title')}
            </h2>
            <p className={styles.sectionDesc}>{t('ux.home.scenarios.desc')}</p>
          </div>
          <ButtonLink to="/simulate/person" variant="text" iconAfter="arrow-right">
            {t('ux.home.scenarios.all')}
          </ButtonLink>
        </div>
        <div className={styles.scenarios}>
          <ScenarioCard
            recommended
            icon="user-round-x"
            title={t('ux.home.card.ato.title')}
            situation={t('ux.home.card.ato.situation')}
            check={t('ux.home.card.ato.check')}
            tags={[t('ux.home.card.ato.tags')]}
            foot={atoSteps !== null ? t('ux.home.card.ato.foot', { count: atoSteps, n: n(atoSteps) }) : null}
            to={flowPath('S13', 'review')}
          />
          <ScenarioCard
            icon="user-round-cog"
            title={t('ux.home.card.insider.title')}
            situation={t('ux.home.card.insider.situation')}
            check={t('ux.home.card.insider.check')}
            tags={[t('ux.home.card.threat')]}
            foot={
              insiderSteps !== null
                ? t('ux.flow.requests', { count: insiderSteps, n: n(insiderSteps) })
                : null
            }
            to={flowPath('S16', 'review')}
          />
          <ScenarioCard
            icon="bot"
            title={t('ux.home.card.agent.title')}
            situation={t('ux.home.card.agent.situation')}
            check={t('ux.home.card.agent.check')}
            tags={agentCases !== null ? [t('ux.home.card.agent.count', { n: n(agentCases) })] : []}
            foot={t('ux.home.card.agent.foot')}
            to="/simulate/agent"
          />
          <ScenarioCard
            icon="layers"
            title={t('ux.home.card.surge.title')}
            situation={t('ux.home.card.surge.situation')}
            check={t('ux.home.card.surge.check')}
            tags={[t('ux.home.card.surge.tag')]}
            foot={
              burst
                ? t('ux.home.card.surge.foot', { most: n(burst.most), measured: n(burst.measured) })
                : null
            }
            to="/simulate/surge"
          />
        </div>
      </section>

      <HowBand />
      <BenchBand />
    </>
  );
}

/**
 * The published recorded run (DEC-17): the operator's measured run of the account takeover with every control's
 * recorded answer, the request it sent and the measurement it belongs to.
 */
function RecordedRun() {
  const { t } = useTranslation();
  const hook = useHook();
  if (hook.isPending) {
    return (
      <section className={styles.record} aria-label={t('ux.home.replay.title')}>
        <Loading rows={5} />
      </section>
    );
  }
  if (hook.isError || !hook.data) {
    return (
      <section className={styles.record} aria-label={t('ux.home.replay.title')}>
        {hook.error instanceof HttpError && hook.error.status === 404 ? (
          <EmptyState>{t('ux.home.replay.none')}</EmptyState>
        ) : (
          <ErrorState onRetry={() => void hook.refetch()} />
        )}
      </section>
    );
  }
  return <RecordedRunCard column={hook.data.attacker} />;
}

function RecordedRunCard({ column }: { readonly column: HookColumn }) {
  const { t, i18n } = useTranslation();
  const anatomy = useAnatomy(column.runId, 1);
  const received = useReceived(column.runId, 1);
  const options = useLabOptions();
  const n = (value: number) => formatNumber(value, i18n.language);
  const layers = column.result.layers;
  const layerOf = (control: string) => layers.find((layer) => layer.control === control) ?? null;
  const contexa = layerOf('D');
  const rows: LaneRow[] = CONTROL_ORDER.map((control) => {
    const layer = layerOf(control);
    return {
      control,
      verdict: layer
        ? controlVerdict(
            control,
            { outcome: layer.outcome, ruleId: layer.ruleId },
            control === 'D' && layer.verdict
              ? { finalAction: layer.verdict, unresolved: layer.evidence.unresolved }
              : null,
          )
        : null,
      items: layer?.evidence.deliveredItems ?? null,
      ms: layer?.evidence.responseMs ?? null,
    };
  });
  const existing = EXISTING.map((control) => layerOf(control)?.evidence.deliveredItems ?? 0);
  const sameExisting = existing.every((items) => items === existing[0]);
  const resource = anatomy.data?.context.resource ?? null;
  const requested = (resource as { readonly requestedItems?: number | null } | null)?.requestedItems ?? null;
  const device = received.data?.usualVsNow.find((row) => row.dimension === 'device') ?? null;
  const employee =
    options.data?.cases.find((labCase) => labCase.key === column.caseKey)?.conditions.employee ?? null;
  const summary = [
    requested !== null ? t('ux.home.replay.export', { n: n(requested) }) : null,
    employee
      ? t('ux.home.replay.account', { name: t(`ux.person.${employee}`, { defaultValue: employee }) })
      : null,
    device
      ? `${deviceWords(device.now)}${device.inUsual === 'false' ? ` (${t('ux.flag.deviation')})` : ''}`
      : null,
    companyClock(t, column.result.companyTime),
  ].filter((part): part is string => part !== null);
  return (
    <section className={styles.record} aria-labelledby="record-title">
      <div className={styles.recordHead}>
        <Icon name="radio-tower" size="md" className={styles.recordIcon} />
        <h2 id="record-title" className={styles.recordTitle}>
          {t('ux.home.replay.title')}
        </h2>
        <CodeChip value={column.runId} copy />
        <time
          className={styles.recordTime}
          dateTime={column.startedAt}
          title={localTime(column.startedAt, i18n.language)}
        >
          {formatUtc(column.startedAt)} {t('ux.time.zone')}
        </time>
      </div>
      <div className={styles.recordRequest}>
        <p className={styles.requestLine}>
          {resource?.httpMethod ? <span className={styles.method}>{resource.httpMethod}</span> : null}
          <code className={styles.path}>{resource?.requestPath ?? '…'}</code>
        </p>
        <p className={styles.requestSummary}>{summary.join(' · ')}</p>
      </div>
      <ControlLanes rows={rows} label={t('ux.home.replay.lanes')} />
      <div className={styles.tally}>
        <div>
          <p className={styles.tallyLabel}>{t('ux.home.replay.existing')}</p>
          <p className={styles.tallyValue}>
            {sameExisting
              ? t('ux.home.replay.timesFour', { n: n(existing[0] ?? 0) })
              : t('ux.facts.items', {
                  count: existing.reduce((sum, items) => sum + items, 0),
                  n: n(existing.reduce((sum, items) => sum + items, 0)),
                })}
          </p>
        </div>
        <div>
          <p className={styles.tallyLabel}>{t('ux.home.replay.contexa')}</p>
          <p className={styles.tallyValue}>
            {contexa
              ? t('ux.facts.items', {
                  count: contexa.evidence.deliveredItems,
                  n: n(contexa.evidence.deliveredItems),
                })
              : '—'}
          </p>
        </div>
      </div>
      <p className={styles.recordNote}>
        {t('ux.home.replay.measurement', {
          runs: n(column.measurement.runs),
          same: n(column.measurement.sameResult),
        })}
      </p>
    </section>
  );
}
