import { Fragment } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams } from 'react-router-dom';
import {
  BENCH_IDS,
  BENCH_NAMES,
  BUNDLE_PATH,
  benchOf,
  readable,
  useBundle,
  words,
  type BenchImpact,
  type Bundle,
} from '../../bench/bundle';
import { formatNumber, formatUtc } from '../../format';
import {
  ButtonAnchor,
  ButtonLink,
  Card,
  CodeChip,
  EmptyState,
  ErrorState,
  Loading,
  PageHead,
  SummaryBar,
  TabPanel,
  Tabs,
} from '../../ui';
import BenchDetail from './BenchDetail';
import { DirectionWord, ImpactTable, LimitsCard, PairedCell, ShareCell } from './BenchParts';
import styles from './Bench.module.css';
import { breakable, chunked } from '../../ui/breakable';

const VIEWS = ['overview', ...BENCH_IDS, 'method'] as const;
type View = (typeof VIEWS)[number];

/**
 * The standard benchmarks (기획안 8절, DEC-54 ~ DEC-57): public benchmarks run on their official harnesses and scorers,
 * every case without and with Contexa. The overview, one page per benchmark and the method; every value is the result
 * bundle's, and the limits stand beside the results.
 */
export default function BenchmarksPage() {
  const { bench = 'overview' } = useParams();
  const navigate = useNavigate();
  const { t, i18n } = useTranslation();
  const bundle = useBundle();
  const view: View | null = (VIEWS as readonly string[]).includes(bench) ? (bench as View) : null;
  const data = readable(bundle.data) ? bundle.data : null;
  const shown = view && view !== 'overview' && view !== 'method' && data ? benchOf(data, view) : null;
  const title =
    view === 'method'
      ? t('ux.bench.method.title')
      : shown
        ? words(shown.title, i18n.language)
        : t('ux.bench.title');
  return (
    <>
      <PageHead
        kicker={shown ? <CodeChip value={shown.version} /> : undefined}
        title={title}
        desc={
          shown
            ? words(shown.description, i18n.language)
            : view === 'method'
              ? t('ux.bench.method.desc')
              : t('ux.bench.desc')
        }
        actions={
          <ButtonAnchor href={BUNDLE_PATH} icon="download">
            {t('ux.bench.download')}
          </ButtonAnchor>
        }
      />
      <Tabs
        idBase="bench"
        label={t('ux.bench.tabs')}
        value={view ?? 'overview'}
        onChange={(id) => navigate(id === 'overview' ? '/benchmarks' : `/benchmarks/${id}`)}
        items={VIEWS.map((id) => ({
          id,
          label: id === 'overview' || id === 'method' ? t(`ux.bench.tab.${id}`) : (BENCH_NAMES[id] ?? id),
        }))}
      />
      <TabPanel idBase="bench" id={view ?? 'overview'}>
        {bundle.isPending ? (
          <Loading rows={8} />
        ) : !bundle.data ? (
          // ST-67: the bundle could not be read.
          <ErrorState onRetry={() => void bundle.refetch()}>{t('ux.bench.failed')}</ErrorState>
        ) : !data ? (
          // ST-68: a bundle of another format.
          <ErrorState>{t('ux.bench.format')}</ErrorState>
        ) : !view ? (
          // ST-69: no such benchmark.
          <EmptyState
            action={
              <ButtonLink to="/benchmarks" variant="secondary">
                {t('ux.bench.toOverview')}
              </ButtonLink>
            }
          >
            {t('ux.bench.missing')}
          </EmptyState>
        ) : view === 'overview' ? (
          <Overview bundle={data} />
        ) : view === 'method' ? (
          <Method bundle={data} />
        ) : shown ? (
          <BenchDetail bundle={data} bench={shown} />
        ) : (
          <EmptyState>{t('ux.bench.missing')}</EmptyState>
        )}
      </TabPanel>
    </>
  );
}

function Overview({ bundle }: { readonly bundle: Bundle }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const program = bundle.program;
  const impact: { readonly bench: string; readonly row: BenchImpact }[] = bundle.benchmarks.flatMap((bench) =>
    bench.impact.filter((row) => row.overview).map((row) => ({ bench: bench.id, row })),
  );
  const testLabel = (bench: string, test: string) => {
    const found = benchOf(bundle, bench)?.tests.find((item) => item.id === test);
    return found ? words(found.label, i18n.language) : test;
  };
  return (
    <div className={styles.stack}>
      <SummaryBar
        label={t('ux.bench.strip.label')}
        items={[
          {
            label: t('ux.bench.strip.freezes'),
            value: t('ux.bench.strip.freezesValue', { n: n(bundle.freezes.length) }),
          },
          { label: t('ux.bench.strip.harness'), value: formatUtc(program.harness.checkedAt).slice(0, 10) },
          {
            label: t('ux.bench.strip.victim'),
            value: <code className={styles.code}>{breakable(program.models.victim)}</code>,
          },
          {
            label: t('ux.bench.strip.judges'),
            value: (
              <span className={styles.models}>
                <code className={styles.code}>{breakable(program.models.layer1)}</code>
                <code className={styles.code}>{breakable(program.models.layer2)}</code>
              </span>
            ),
          },
          { label: t('ux.bench.strip.spend'), value: `$${formatNumber(program.spendUsd, i18n.language, 2)}` },
        ]}
      />
      <Card title={t('ux.bench.matrix.title')} sub={t('ux.bench.matrix.sub')} flush>
        <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
          <table className={styles.table} data-stack>
            <caption className="ux-sr-only">{t('ux.bench.matrix.title')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.bench.col.test')}</th>
                <th scope="col">{t('ux.bench.col.metric')}</th>
                <th scope="col">{t('ux.bench.col.unprotected')}</th>
                <th scope="col">{t('ux.bench.col.protected')}</th>
                <th scope="col">{t('ux.bench.col.paired')}</th>
                <th scope="col" data-numeric>
                  {t('ux.bench.col.sample')}
                </th>
              </tr>
            </thead>
            <tbody>
              {bundle.benchmarks.map((bench) => (
                <Fragment key={bench.id}>
                  <tr className={styles.groupRow}>
                    <th scope="colgroup" colSpan={6}>
                      <ButtonLink
                        to={`/benchmarks/${bench.id}`}
                        variant="text"
                        size="sm"
                        icon="chevron-right"
                      >
                        {bench.name}
                      </ButtonLink>
                      <span className={styles.shareSub}>{bench.version}</span>
                    </th>
                  </tr>
                  {bench.tests
                    .filter((test) => test.matrix)
                    .map((test) => (
                      <tr key={test.id}>
                        <th scope="row">
                          <span className={styles.testName}>{words(test.label, i18n.language)}</span>
                          <span className={styles.shareSub}>
                            {words(test.note, i18n.language)} · {t('ux.bench.freeze', { id: test.freeze })}
                          </span>
                        </th>
                        <td data-k={t('ux.bench.col.metric')}>
                          <span className={styles.testName}>{test.metric}</span>
                          <DirectionWord direction={test.direction} />
                        </td>
                        <td data-k={t('ux.bench.col.unprotected')}>
                          <ShareCell share={test.unprotected} bench={bench.id} />
                        </td>
                        <td data-k={t('ux.bench.col.protected')}>
                          <ShareCell share={test.protected} bench={bench.id} strong />
                        </td>
                        <td data-k={t('ux.bench.col.paired')}>
                          {test.paired ? (
                            <PairedCell paired={test.paired} direction={test.direction} />
                          ) : test.weakVariants !== undefined ? (
                            <span className={styles.shareValue}>
                              {t('ux.bench.weak', { n: n(test.weakVariants) })}
                            </span>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td data-numeric data-k={t('ux.bench.col.sample')}>
                          {n(test.sample)}
                        </td>
                      </tr>
                    ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title={t('ux.bench.impact.title')} sub={t('ux.bench.impact.sub')} flush>
        <ImpactTable rows={impact} testLabel={testLabel} />
      </Card>
      <Card title={t('ux.bench.published.title')}>
        <ul className={styles.facts} data-wide>
          {program.harness.packages.map((pkg) => (
            <li key={pkg.name}>
              {pkg.filesChecked !== undefined
                ? t('ux.bench.published.package', {
                    name: pkg.name,
                    version: pkg.version,
                    checked: n(pkg.filesChecked),
                    changed: n(pkg.filesChanged),
                  })
                : t('ux.bench.published.commit', {
                    name: pkg.name,
                    version: pkg.version,
                    changed: n(pkg.filesChanged),
                  })}
            </li>
          ))}
          <li>{t('ux.bench.published.checked', { at: formatUtc(program.harness.checkedAt) })}</li>
          <li>{t('ux.bench.published.promptfoo', { version: program.harness.promptfoo.version })}</li>
          <li>{t('ux.bench.published.frozen', { n: n(bundle.freezes.length) })}</li>
          <li>{t('ux.bench.published.below')}</li>
        </ul>
      </Card>
      <LimitsCard limits={bundle.limits} />
    </div>
  );
}

/** 방법 · 재현 (기획안 8.2): the frozen versions, the harness proof, the order of the tests, the statistics and the files. */
function Method({ bundle }: { readonly bundle: Bundle }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const ordered = [...bundle.freezes].sort((a, b) => a.frozenAt.localeCompare(b.frozenAt));
  const methods = new Set(
    bundle.benchmarks.flatMap((bench) =>
      bench.tests.flatMap((test) => [test.protected?.method, test.unprotected?.method]),
    ),
  );
  const reproduction = bundle.limits.find((limit) => limit.id === 'reproduction');
  return (
    <div className={styles.stack}>
      <Card title={t('ux.bench.method.freezes')} sub={t('ux.bench.method.freezesSub')} flush>
        <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
          <table className={styles.table} data-stack>
            <caption className="ux-sr-only">{t('ux.bench.method.freezes')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.bench.method.col.freeze')}</th>
                <th scope="col">{t('ux.bench.method.col.at')}</th>
                <th scope="col">{t('ux.bench.method.col.bundle')}</th>
                <th scope="col">{t('ux.bench.method.col.core')}</th>
                <th scope="col">{t('ux.bench.method.col.path')}</th>
                <th scope="col">{t('ux.bench.method.col.used')}</th>
              </tr>
            </thead>
            <tbody>
              {ordered.map((freeze) => (
                <tr key={freeze.id}>
                  <th scope="row">
                    <span className={styles.testName}>{freeze.id}</span>
                    <code className={styles.hash} title={freeze.sha256}>
                      sha256 {chunked(`${freeze.sha256.slice(0, 12)}…`)}
                    </code>
                  </th>
                  <td
                    data-k={t('ux.bench.method.col.at')}
                  >{`${formatUtc(freeze.frozenAt)} ${t('ux.runs.utc')}`}</td>
                  <td data-k={t('ux.bench.method.col.bundle')}>
                    <code className={styles.code}>{breakable(freeze.promptBundle)}</code>
                  </td>
                  <td data-k={t('ux.bench.method.col.core')}>
                    {t('ux.bench.method.core', {
                      commit: freeze.coreCommit.slice(0, 8),
                      n: n(freeze.coreChangedFiles),
                    })}
                  </td>
                  <td data-k={t('ux.bench.method.col.path')}>
                    {t('ux.bench.method.path', { n: n(freeze.decisionPathFiles) })}
                    <code className={styles.hash}>{chunked(freeze.decisionPathHash.slice(0, 12))}</code>
                  </td>
                  <td data-k={t('ux.bench.method.col.used')}>{freeze.usedBy.join(' · ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <div className={styles.split}>
        <Card title={t('ux.bench.method.harness')}>
          <ul className={styles.facts}>
            {bundle.program.harness.packages.map((pkg) => (
              <li key={pkg.name}>
                {pkg.filesChecked !== undefined
                  ? t('ux.bench.published.package', {
                      name: pkg.name,
                      version: pkg.version,
                      checked: n(pkg.filesChecked),
                      changed: n(pkg.filesChanged),
                    })
                  : t('ux.bench.published.commit', {
                      name: pkg.name,
                      version: pkg.version,
                      changed: n(pkg.filesChanged),
                    })}
              </li>
            ))}
            <li>{t('ux.bench.published.checked', { at: formatUtc(bundle.program.harness.checkedAt) })}</li>
            <li>
              {t('ux.bench.published.promptfoo', { version: bundle.program.harness.promptfoo.version })}
            </li>
          </ul>
        </Card>
        <Card title={t('ux.bench.method.stats')}>
          <ul className={styles.facts}>
            {methods.has('clopper-pearson') ? <li>{t('ux.bench.method.clopper')}</li> : null}
            {methods.has('wilson') ? <li>{t('ux.bench.method.wilson')}</li> : null}
            <li>{t('ux.bench.method.mcnemar')}</li>
            <li>{t('ux.bench.method.upper')}</li>
            <li>{t('ux.bench.method.derived')}</li>
          </ul>
        </Card>
      </div>
      <div className={styles.split}>
        <Card title={t('ux.bench.method.order')}>
          <ol className={styles.order}>
            {ordered.map((freeze) => (
              <li key={freeze.id}>
                {t('ux.bench.method.orderItem', {
                  at: formatUtc(freeze.frozenAt),
                  freeze: freeze.id,
                  tests: freeze.usedBy.join(' · '),
                })}
              </li>
            ))}
          </ol>
        </Card>
        <Card title={t('ux.bench.method.reproduction')}>
          <p className={styles.para}>{reproduction ? words(reproduction, i18n.language) : '—'}</p>
          <p className={styles.para}>{t('ux.bench.method.reproductionNow')}</p>
        </Card>
      </div>
      <Card
        title={t('ux.bench.method.sources')}
        sub={t('ux.bench.method.sourcesSub', { n: n(bundle.sources.length) })}
        actions={
          <ButtonAnchor href={BUNDLE_PATH} icon="download" size="sm">
            {t('ux.bench.download')}
          </ButtonAnchor>
        }
        flush
      >
        <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
          <table className={styles.table} data-stack>
            <caption className="ux-sr-only">{t('ux.bench.method.sources')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.bench.method.col.file')}</th>
                <th scope="col">sha256</th>
              </tr>
            </thead>
            <tbody>
              {bundle.sources.map((source) => (
                <tr key={source.path}>
                  <th scope="row">
                    <code className={styles.code}>{breakable(source.path)}</code>
                  </th>
                  <td data-k={'sha256'}>
                    <code className={styles.hash}>{chunked(source.sha256, 8)}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
