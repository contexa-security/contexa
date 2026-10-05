import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useStats } from '../api/queries';
import type { StatsView } from '../api/types';
import { AppHeader } from '../components/AppHeader';
import { StateScreen } from '../components/StateScreen';
import { VerdictChip } from '../components/VerdictChip';
import { decisionMix, percent, seconds, utcMinute } from '../domain/stats';
import styles from './StatsPage.module.css';

/**
 * Execution statistics (deck p.17): an operations record of the real runs, kept apart from the benchmark. Every
 * number comes from the server's count of the stored runs; the page only formats it and shows how it was counted.
 */
export default function StatsPage() {
  const { t } = useTranslation();
  const stats = useStats();

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" className={styles.page}>
        <header className={styles.header}>
          <p className={styles.badge}>{t('stats.badge')}</p>
          <h1 className={styles.title}>{t('stats.title')}</h1>
          <p className={styles.lead}>{t('stats.lead')}</p>
        </header>
        {stats.isPending ? <StateScreen kind="loading" /> : null}
        {stats.isError ? <StateScreen kind="error" onRetry={() => void stats.refetch()} /> : null}
        {stats.data && stats.data.runs.completed === 0 ? (
          <p className={styles.empty}>{t('stats.empty')}</p>
        ) : null}
        {stats.data && stats.data.runs.completed > 0 ? <StatsBody view={stats.data} /> : null}
      </main>
    </>
  );
}

function StatsBody({ view }: { readonly view: StatsView }) {
  const { t, i18n } = useTranslation();
  const count = new Intl.NumberFormat(i18n.language === 'ko' ? 'ko-KR' : 'en-US');
  const agreement = percent(view.agreement.agreeing, view.agreement.repetitions);
  const p50 = seconds(view.decisionTime.p50Ms);
  const p95 = seconds(view.decisionTime.p95Ms);
  const mix = decisionMix(view.engineActions);

  return (
    <>
      <dl className={styles.figures}>
        <div className={styles.figure}>
          <dt>{t('stats.runs')}</dt>
          <dd className={styles.value}>{count.format(view.runs.completed)}</dd>
          <dd className={styles.detail}>
            {t('stats.runsDetail', {
              today: count.format(view.runs.today),
              live: count.format(view.runs.live),
            })}
          </dd>
        </div>
        <div className={styles.figure}>
          <dt>{t('stats.decisionTime')}</dt>
          <dd className={styles.value}>
            {p50 === null ? t('stats.none') : t('stats.seconds', { value: p50 })}
          </dd>
          <dd className={styles.detail}>
            {p95 === null
              ? t('stats.noDecisions')
              : t('stats.decisionTimeDetail', {
                  p95: t('stats.seconds', { value: p95 }),
                  count: count.format(view.decisionTime.decisions),
                })}
          </dd>
        </div>
        <div className={styles.figure}>
          <dt>{t('stats.agreement')}</dt>
          {agreement === null ? (
            <dd className={styles.value}>{t('stats.agreementNone')}</dd>
          ) : (
            <>
              <dd className={styles.value}>{`${agreement}%`}</dd>
              <dd className={styles.detail}>
                {t('stats.agreementDetail', {
                  agreeing: count.format(view.agreement.agreeing),
                  repetitions: count.format(view.agreement.repetitions),
                  scenes: view.agreement.recordings.length,
                })}
              </dd>
            </>
          )}
        </div>
        <div className={styles.figure}>
          <dt>{t('stats.unresolved')}</dt>
          <dd className={styles.value}>{count.format(view.unresolved.technical)}</dd>
          <dd className={styles.detail}>
            {t('stats.unresolvedDetail', { count: count.format(view.unresolved.noNewAnalysis) })}
          </dd>
        </div>
      </dl>

      <section className={styles.section} aria-labelledby="stats-layers">
        <h2 id="stats-layers" className={styles.sectionTitle}>
          {t('stats.layers.title')}
        </h2>
        {/* Explicit roles keep the table semantics when narrow screens lay each row out as a card. */}
        <div className={styles.tableWrap}>
          <table className={styles.table} role="table">
            <caption className={styles.caption}>{t('stats.layers.caption')}</caption>
            <thead role="rowgroup">
              <tr role="row">
                <th scope="col" role="columnheader">
                  {t('stats.layers.control')}
                </th>
                {COLUMNS.map((column) => (
                  <th key={column} scope="col" role="columnheader">
                    {t(`stats.layers.${column}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody role="rowgroup">
              {view.layers.map((layer) => {
                const values = {
                  leaked: share(layer.threat.leaked, layer.threat.runs, t),
                  stopped: share(layer.threat.stopped, layer.threat.runs, t),
                  blocked: share(layer.normal.blocked, layer.normal.runs, t),
                  challenged: share(layer.normal.challenged, layer.normal.runs, t),
                };
                return (
                  <tr key={layer.control} role="row" data-control={layer.control}>
                    <th scope="row" role="rowheader">
                      <span className={styles.control}>{t(`control.${layer.control}.name`)}</span>
                      <span className={styles.config}>{t(`control.${layer.control}.config`)}</span>
                    </th>
                    {COLUMNS.map((column) => (
                      <td key={column} role="cell">
                        <span className={styles.cellLabel} aria-hidden="true">
                          {t(`stats.layers.${column}`)}
                        </span>
                        <span data-part="value">{values[column]}</span>
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <p className={styles.note}>
          {t('stats.layers.scope', {
            threat: count.format(view.scope.threatRuns),
            normal: count.format(view.scope.normalRuns),
            other: count.format(view.scope.otherRuns),
          })}
        </p>
      </section>

      <section className={styles.section} aria-labelledby="stats-mix">
        <h2 id="stats-mix" className={styles.sectionTitle}>
          {t('stats.mix.title')}
        </h2>
        <p className={styles.note}>{t('stats.mix.caption', { count: count.format(mix.total) })}</p>
        {mix.total > 0 ? (
          <div className={styles.bar} aria-hidden="true">
            {mix.segments
              .filter((segment) => segment.count > 0)
              .map((segment) => (
                <span
                  key={segment.action}
                  className={styles.segment}
                  data-verdict={segment.action}
                  style={{ inlineSize: `${segment.share}%` }}
                />
              ))}
          </div>
        ) : null}
        <ul className={styles.legend}>
          {mix.segments.map((segment) => (
            <li key={segment.action} className={styles.legendItem}>
              <VerdictChip verdict={segment.action} />
              <span className={styles.legendCount}>
                {mix.total > 0
                  ? t('stats.mix.count', { count: count.format(segment.count), percent: segment.share })
                  : count.format(segment.count)}
              </span>
            </li>
          ))}
        </ul>
      </section>

      <section className={styles.section} aria-labelledby="stats-method">
        <h2 id="stats-method" className={styles.sectionTitle}>
          {t('stats.method.title')}
        </h2>
        <ul className={styles.method}>
          <li>{t('stats.method.scope', { failed: count.format(view.runs.failed) })}</li>
          <li>{t('stats.method.decisive')}</li>
          <li>{t('stats.method.challenge')}</li>
          <li>{t('stats.method.unresolved')}</li>
        </ul>
        {view.spec ? (
          <details className={styles.spec}>
            <summary>{t('stats.spec.title', { count: view.specCount })}</summary>
            <dl className={styles.specList}>
              <dt>{t('stats.spec.engine')}</dt>
              <dd>{view.spec.engineVersion}</dd>
              <dt>{t('stats.spec.mode')}</dt>
              <dd>{view.spec.effectiveMode}</dd>
              <dt>{t('stats.spec.chatModel')}</dt>
              <dd>{view.spec.chatModel}</dd>
              <dt>{t('stats.spec.embeddingModel')}</dt>
              <dd>{view.spec.embeddingModel}</dd>
              <dt>{t('stats.spec.timeZone')}</dt>
              <dd>{view.spec.timeZone}</dd>
              <dt>{t('stats.spec.commit')}</dt>
              <dd className={styles.mono}>{view.spec.codeCommit}</dd>
              <dt>{t('stats.spec.hash')}</dt>
              <dd className={styles.mono}>{view.spec.specHash}</dd>
            </dl>
          </details>
        ) : null}
      </section>

      <p className={styles.updated}>
        <time dateTime={view.computedAt}>{t('stats.updated', { time: utcMinute(view.computedAt) })}</time>
      </p>
    </>
  );
}

/** The table's result columns: two for attack scenes, two for normal work. */
const COLUMNS = ['leaked', 'stopped', 'blocked', 'challenged'] as const;

/** "k / n (p%)", or a dash when the column counted nothing. */
function share(part: number, whole: number, t: TFunction): string {
  const value = percent(part, whole);
  return value === null ? t('stats.none') : t('stats.layers.cell', { part, whole, percent: value });
}
