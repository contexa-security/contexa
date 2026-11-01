import { useTranslation } from 'react-i18next';
import {
  BENCH_NAMES,
  digitsOf,
  pText,
  percent,
  shareText,
  words,
  type BenchImpact,
  type BenchLimit,
  type BenchPaired,
  type BenchShare,
} from '../../bench/bundle';
import { formatNumber } from '../../format';
import { Badge, Card } from '../../ui';
import styles from './Bench.module.css';

/** A share in a table cell: the point, then the counts and the interval or, below 1%, the upper bound apart (PC-9). */
export function ShareCell({
  share,
  bench,
  strong = false,
}: {
  readonly share: BenchShare | null;
  readonly bench: string;
  readonly strong?: boolean;
}) {
  const { t, i18n } = useTranslation();
  if (!share) {
    return <span className={styles.muted}>—</span>;
  }
  const text = shareText(share, i18n.language, digitsOf(bench));
  return (
    <span className={styles.share}>
      <span className={strong ? styles.shareStrong : styles.shareValue}>{text.value}</span>
      <span className={styles.shareSub}>
        <span className={styles.piece}>{text.counts}</span>
        {text.interval ? ' ' : null}
        {text.interval ? <span className={styles.piece}>· {text.interval}</span> : null}
      </span>
      {text.upper ? (
        <span className={styles.shareUpper}>{t('ux.bench.share.upper', { value: text.upper })}</span>
      ) : null}
      {text.construction ? (
        <span className={styles.shareSub} title={t('ux.bench.share.constructionTitle')}>
          {t('ux.bench.share.construction')}
        </span>
      ) : null}
    </span>
  );
}

/**
 * A paired comparison in words that follow the metric: for a share where lower is better (attacks that got through)
 * the cases only the unprotected run failed were stopped; where higher is better (tasks solved, attacks withstood) the
 * cases only the protected run held got better.
 */
export function PairedCell({
  paired,
  direction,
}: {
  readonly paired: BenchPaired | null;
  readonly direction: 'lower' | 'higher';
}) {
  const { t, i18n } = useTranslation();
  if (!paired) {
    return <span className={styles.muted}>—</span>;
  }
  const n = (value: number) => formatNumber(value, i18n.language);
  const good = direction === 'lower' ? paired.onlyUnprotected : paired.onlyProtected;
  const bad = direction === 'lower' ? paired.onlyProtected : paired.onlyUnprotected;
  return (
    <span className={styles.share}>
      <span className={styles.shareValue}>
        {t(`ux.bench.paired.${direction}`, { good: n(good), bad: n(bad) })}
      </span>
      <span className={styles.shareSub}>{`p ${pText(paired.p, i18n.language)}`}</span>
    </span>
  );
}

export function OwnBadge() {
  const { t } = useTranslation();
  return <Badge tone="line">{t('ux.bench.own')}</Badge>;
}

export function DirectionWord({ direction }: { readonly direction: 'lower' | 'higher' }) {
  const { t } = useTranslation();
  return <span className={styles.direction}>{t(`ux.bench.direction.${direction}`)}</span>;
}

export interface IntervalRow {
  readonly key: string;
  readonly label: string;
  readonly sub?: string;
  readonly share: BenchShare | null;
  readonly contexa: boolean;
}

/**
 * The interval chart of a benchmark's results (기획안 8.2): one bar per run on a shared axis, the bar to the point and
 * the whisker over the 95% interval. The values are written beside every bar, so the chart is read as a list.
 */
export function IntervalChart({
  label,
  rows,
  bench,
}: {
  readonly label: string;
  readonly rows: readonly IntervalRow[];
  readonly bench: string;
}) {
  const { t, i18n } = useTranslation();
  const top = Math.max(...rows.map((row) => row.share?.high ?? row.share?.rate ?? 0), 0.01);
  // The axis ends at the next round step above the largest end: 5% steps up to 20%, 10% steps past it.
  const step = top <= 0.2 ? 0.05 : 0.1;
  const axis = Math.min(1, Math.ceil(top / step) * step);
  const at = (value: number) => `${Math.min(100, (value / axis) * 100)}%`;
  const ticks = Array.from({ length: Math.round(axis / step) + 1 }, (_, index) => index * step);
  return (
    <figure className={styles.chart} aria-label={label}>
      <ul className={styles.chartRows}>
        {rows.map((row) => {
          const text = row.share ? shareText(row.share, i18n.language, digitsOf(bench)) : null;
          return (
            <li key={row.key} className={styles.chartRow} data-contexa={row.contexa || undefined}>
              <span className={styles.chartName}>
                <span className={styles.chartLabel}>{row.label}</span>
                {row.sub ? <span className={styles.shareSub}>{row.sub}</span> : null}
              </span>
              <span className={styles.chartTrack} aria-hidden="true">
                {row.share ? (
                  <>
                    <span className={styles.chartBar} style={{ inlineSize: at(row.share.rate) }} />
                    {row.share.low !== null && row.share.high !== null ? (
                      <span
                        className={styles.chartWhisker}
                        style={{
                          insetInlineStart: at(row.share.low),
                          inlineSize: `calc(${at(row.share.high)} - ${at(row.share.low)})`,
                        }}
                      />
                    ) : null}
                  </>
                ) : null}
              </span>
              <span className={styles.chartValue}>
                {text ? (
                  <>
                    <b>{text.value}</b>
                    <span className={styles.shareSub}>
                      <span className={styles.piece}>{text.counts}</span>
                      {text.interval ? ' ' : null}
                      {text.interval ? <span className={styles.piece}>· {text.interval}</span> : null}
                      {text.upper ? ' ' : null}
                      {text.upper ? (
                        <span className={styles.piece}>
                          · {t('ux.bench.share.upper', { value: text.upper })}
                        </span>
                      ) : null}
                      {text.construction ? ' ' : null}
                      {text.construction ? (
                        <span className={styles.piece}>· {t('ux.bench.share.construction')}</span>
                      ) : null}
                    </span>
                  </>
                ) : (
                  '—'
                )}
              </span>
            </li>
          );
        })}
      </ul>
      <div className={styles.chartAxis} aria-hidden="true">
        <span />
        <span className={styles.chartTicks}>
          {ticks.map((tick) => (
            <span key={tick} style={{ insetInlineStart: at(tick) }}>
              {percent(tick, i18n.language, 0)}
            </span>
          ))}
        </span>
        <span />
      </div>
    </figure>
  );
}

/** The limits beside the results, never folded (PC-9: unfavourable results and limits on the same screen). */
export function LimitsCard({ limits }: { readonly limits: readonly BenchLimit[] }) {
  const { t, i18n } = useTranslation();
  return (
    <Card title={t('ux.bench.limits.title')} sub={t('ux.bench.limits.sub')}>
      <ul className={styles.limits}>
        {limits.map((limit) => (
          <li key={limit.id}>
            <span>{words(limit, i18n.language)}</span>
            <span className={styles.source}>
              {t('ux.bench.limits.source', { source: words(limit.sourceLabel, i18n.language) })}
            </span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

/** The effect on legitimate work: the same table on the overview and on each benchmark's results. */
export function ImpactTable({
  rows,
  testLabel,
}: {
  readonly rows: readonly { readonly bench: string; readonly row: BenchImpact }[];
  readonly testLabel: (bench: string, test: string) => string;
}) {
  const { t } = useTranslation();
  return (
    <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
      <table className={styles.table} data-stack>
        <caption className="ux-sr-only">{t('ux.bench.impact.title')}</caption>
        <thead>
          <tr>
            <th scope="col">{t('ux.bench.col.test')}</th>
            <th scope="col">{t('ux.bench.col.metricShort')}</th>
            <th scope="col">{t('ux.bench.col.unprotected')}</th>
            <th scope="col">{t('ux.bench.col.protected')}</th>
            <th scope="col">{t('ux.bench.col.paired')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ bench, row }) => (
            <tr key={`${row.test}-${row.metric}`}>
              <th scope="row">
                <span className={styles.testName}>{testLabel(bench, row.test)}</span>
                <span className={styles.shareSub}>{BENCH_NAMES[bench] ?? bench}</span>
              </th>
              <td data-k={t('ux.bench.col.metricShort')}>
                <span className={styles.testName}>
                  {row.metric === 'benign-calls-refused'
                    ? t('ux.bench.metric.benignCallsRefused')
                    : row.metric}
                </span>
                <DirectionWord direction={row.direction} />
                {row.own ? <OwnBadge /> : null}
              </td>
              <td data-k={t('ux.bench.col.unprotected')}>
                <ShareCell share={row.unprotected} bench={bench} />
              </td>
              <td data-k={t('ux.bench.col.protected')}>
                <ShareCell share={row.protected} bench={bench} strong />
              </td>
              <td data-k={t('ux.bench.col.paired')}>
                <PairedCell paired={row.paired} direction={row.direction} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
