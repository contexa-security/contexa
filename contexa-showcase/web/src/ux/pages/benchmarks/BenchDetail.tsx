import { Fragment, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import {
  pText,
  words,
  type AgentDojoBench,
  type Benchmark,
  type BenchShare,
  type Bundle,
  type InjecAgentBench,
  type PromptfooBench,
  type PromptfooRow,
  type WarmPaired,
} from '../../bench/bundle';
import { formatNumber, formatUtc } from '../../format';
import { Badge, Card, CodeChip, KeyValue, Note, TabPanel, Tabs } from '../../ui';
import {
  ImpactTable,
  IntervalChart,
  LimitsCard,
  OwnBadge,
  PairedCell,
  ShareCell,
  type IntervalRow,
} from './BenchParts';
import styles from './Bench.module.css';
import { breakable } from '../../ui/breakable';

const TABS = ['results', 'breakdown', 'variants', 'cases', 'settings'] as const;
type TabId = (typeof TABS)[number];

/** The tabs a benchmark has: Promptfoo has no variants (DEC-56). */
function tabsOf(bench: Benchmark): readonly TabId[] {
  return bench.id === 'promptfoo' ? TABS.filter((tab) => tab !== 'variants') : TABS;
}

/**
 * One benchmark's page (DEC-56): the results with the limits beside them, the breakdown, the variants, the cases the
 * protected agent still failed and the settings. `?tab=` keeps the place; a tab the benchmark lacks opens the results
 * (ST-70).
 */
export default function BenchDetail({
  bundle,
  bench,
}: {
  readonly bundle: Bundle;
  readonly bench: Benchmark;
}) {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const tabs = tabsOf(bench);
  const asked = params.get('tab') as TabId | null;
  const tab: TabId = asked && tabs.includes(asked) ? asked : 'results';
  const limits = bench.limits.flatMap((id) => bundle.limits.filter((limit) => limit.id === id));
  return (
    <div className={styles.stack}>
      <Tabs
        idBase="bench-view"
        label={t('ux.bench.view.tabs', { name: bench.name })}
        value={tab}
        onChange={(id) => setParams(new URLSearchParams({ tab: id }), { replace: true })}
        items={tabs.map((id) => ({ id, label: t(`ux.bench.view.${id}`) }))}
      />
      <TabPanel idBase="bench-view" id={tab}>
        <div className={styles.stack}>
          {tab === 'results' ? (
            <>
              <Results bench={bench} />
              <LimitsCard limits={limits} />
            </>
          ) : tab === 'breakdown' ? (
            <Breakdown bench={bench} />
          ) : tab === 'variants' ? (
            <Variants bench={bench} />
          ) : tab === 'cases' ? (
            <Cases bench={bench} />
          ) : (
            <Settings bundle={bundle} bench={bench} />
          )}
        </div>
      </TabPanel>
    </div>
  );
}

function useLabel(bench: Benchmark) {
  const { i18n } = useTranslation();
  return (test: string) => {
    const found = bench.tests.find((item) => item.id === test);
    return found ? words(found.label, i18n.language) : test;
  };
}

// ── results ──────────────────────────────────────────────────────────────────────────────────────────────────────

function Results({ bench }: { readonly bench: Benchmark }) {
  const { t, i18n } = useTranslation();
  const label = useLabel(bench);
  const test = (id: string) => bench.tests.find((item) => item.id === id) ?? null;
  const unprotected = t('ux.bench.col.unprotected');
  const groups: { readonly key: string; readonly title: string; readonly rows: readonly IntervalRow[] }[] =
    [];
  if (bench.id === 'agentdojo') {
    const remeasured = (id: string) =>
      bench.variants.remeasure.find((row) => row.test === id)?.protected ?? null;
    const a = test('S-1a');
    const c = test('S-1c');
    const s4 = test('S-4');
    groups.push(
      {
        key: 'main',
        title: t('ux.bench.chart.agentdojoMain', {
          metric: 'Targeted ASR',
          n: formatNumber(a?.sample ?? 0, i18n.language),
        }),
        rows: [
          { key: 'u', label: unprotected, sub: 'qwen2.5 7B', share: a?.unprotected ?? null, contexa: false },
          {
            key: 'a',
            label: label('S-1a'),
            sub: words(a?.note ?? { ko: '', en: '' }, i18n.language),
            share: a?.protected ?? null,
            contexa: true,
          },
          {
            key: 'b',
            label: label('S-1b'),
            sub: words(test('S-1b')?.note ?? { ko: '', en: '' }, i18n.language),
            share: test('S-1b')?.protected ?? null,
            contexa: true,
          },
          {
            key: 'a2',
            label: t('ux.bench.chart.remeasured', { test: label('S-1a') }),
            sub: 'test-v2',
            share: remeasured('S-1a'),
            contexa: true,
          },
          {
            key: 'b2',
            label: t('ux.bench.chart.remeasured', { test: label('S-1b') }),
            sub: 'test-v2',
            share: remeasured('S-1b'),
            contexa: true,
          },
        ],
      },
      {
        key: 'second',
        title: t('ux.bench.chart.agentdojoSecond', { n: formatNumber(c?.sample ?? 0, i18n.language) }),
        rows: [
          { key: 'u', label: unprotected, share: c?.unprotected ?? null, contexa: false },
          { key: 'c', label: label('S-1c'), share: c?.protected ?? null, contexa: true },
          {
            key: 'c2',
            label: t('ux.bench.chart.remeasured', { test: label('S-1c') }),
            sub: 'test-v2',
            share: remeasured('S-1c'),
            contexa: true,
          },
        ],
      },
      {
        key: 's4',
        title: t('ux.bench.chart.agentdojoS4', { n: formatNumber(s4?.sample ?? 0, i18n.language) }),
        rows: [
          { key: 'u', label: unprotected, share: s4?.unprotected ?? null, contexa: false },
          { key: 's4', label: label('S-4'), share: s4?.protected ?? null, contexa: true },
        ],
      },
    );
  } else {
    groups.push({
      key: 'main',
      title: t('ux.bench.chart.metric', { metric: bench.tests[0]?.metric ?? '' }),
      rows: bench.tests.flatMap((item) => [
        {
          key: `${item.id}-u`,
          label: `${words(item.label, i18n.language)} · ${unprotected}`,
          share: item.unprotected,
          contexa: false,
        },
        {
          key: `${item.id}-p`,
          label: `${words(item.label, i18n.language)} · ${t('ux.bench.col.protected')}`,
          share: item.protected,
          contexa: true,
        },
      ]),
    });
  }
  const direction = bench.tests[0]?.direction ?? 'lower';
  return (
    <>
      <Card title={t('ux.bench.view.resultsTitle')} sub={t(`ux.bench.chart.sub.${direction}`)}>
        <div className={styles.charts}>
          {groups.map((group) => (
            <div key={group.key} className={styles.chartGroup}>
              <h3 className={styles.groupTitle}>{group.title}</h3>
              <IntervalChart label={group.title} rows={group.rows} bench={bench.id} />
            </div>
          ))}
        </div>
      </Card>
      <Card title={t('ux.bench.view.testsTitle')} sub={t('ux.bench.matrix.sub')} flush>
        <TestsTable bench={bench} />
      </Card>
      {bench.impact.length > 0 ? (
        <Card title={t('ux.bench.impact.title')} sub={t('ux.bench.impact.sub')} flush>
          <ImpactTable
            rows={bench.impact.map((row) => ({ bench: bench.id, row }))}
            testLabel={(_, id) => label(id)}
          />
        </Card>
      ) : null}
      {bench.id === 'injecagent' ? <AttackerCalls bench={bench} /> : null}
      {bench.id === 'promptfoo' ? <RiskyCalls bench={bench} /> : null}
    </>
  );
}

function TestsTable({ bench }: { readonly bench: Benchmark }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const executed = bench.tests.some((test) => test.executedOnly);
  return (
    <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
      <table className={styles.table} data-stack>
        <caption className="ux-sr-only">{t('ux.bench.view.testsTitle')}</caption>
        <thead>
          <tr>
            <th scope="col">{t('ux.bench.col.test')}</th>
            <th scope="col">{t('ux.bench.col.unprotected')}</th>
            <th scope="col">{t('ux.bench.col.protected')}</th>
            {executed ? <th scope="col">{t('ux.bench.col.executed')}</th> : null}
            <th scope="col">{t('ux.bench.col.paired')}</th>
            <th scope="col" data-numeric>
              {t('ux.bench.col.sample')}
            </th>
          </tr>
        </thead>
        <tbody>
          {bench.tests.map((test) => (
            <tr key={test.id}>
              <th scope="row">
                <span className={styles.testName}>{words(test.label, i18n.language)}</span>
                <span className={styles.shareSub}>
                  {test.metric} · {t('ux.bench.freeze', { id: test.freeze })}
                </span>
              </th>
              <td data-k={t('ux.bench.col.unprotected')}>
                <ShareCell share={test.unprotected} bench={bench.id} />
              </td>
              <td data-k={t('ux.bench.col.protected')}>
                <ShareCell share={test.protected} bench={bench.id} strong />
              </td>
              {executed ? (
                <td data-k={t('ux.bench.col.executed')}>
                  <ShareCell share={test.executedOnly} bench={bench.id} />
                </td>
              ) : null}
              <td data-k={t('ux.bench.col.paired')}>
                {test.paired ? (
                  <PairedCell paired={test.paired} direction={test.direction} />
                ) : test.weakVariants !== undefined ? (
                  t('ux.bench.weak', { n: n(test.weakVariants) })
                ) : (
                  '—'
                )}
              </td>
              <td data-numeric data-k={t('ux.bench.col.sample')}>
                {n(test.sample)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {executed ? <p className={styles.tableNote}>{t('ux.bench.executedNote')}</p> : null}
    </div>
  );
}

function AttackerCalls({ bench }: { readonly bench: InjecAgentBench }) {
  const { t } = useTranslation();
  return (
    <Card
      title={t('ux.bench.inj.attackerTitle')}
      sub={t('ux.bench.inj.attackerSub')}
      actions={<OwnBadge />}
      flush
    >
      <SimpleRows
        caption={t('ux.bench.inj.attackerTitle')}
        head={[t('ux.bench.inj.setting'), t('ux.bench.inj.refused')]}
        rows={bench.breakdown.settings.map((row) => [
          row.setting,
          <ShareCell key="s" share={row.attackerCallsRefused} bench={bench.id} strong />,
        ])}
      />
    </Card>
  );
}

function RiskyCalls({ bench }: { readonly bench: PromptfooBench }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const risky = bench.breakdown.riskyToolCalls;
  return (
    <Card title={t('ux.bench.pf.riskyTitle')} sub={t('ux.bench.pf.riskySub')} actions={<OwnBadge />} flush>
      <SimpleRows
        caption={t('ux.bench.pf.riskyTitle')}
        head={[t('ux.bench.pf.tool'), t('ux.bench.col.unprotected'), t('ux.bench.col.protected')]}
        rows={[
          ...risky.tools.map((row) => [
            <code key="c" className={styles.code}>
              {breakable(row.tool)}
            </code>,
            n(row.unprotected),
            n(row.protected),
          ]),
          [
            <b key="b">{t('ux.bench.pf.riskyTotal')}</b>,
            <b key="u">{n(risky.unprotected)}</b>,
            <b key="p">{n(risky.protected)}</b>,
          ],
        ]}
      />
    </Card>
  );
}

/** A plain table of a few columns (the first is the row's name). */
function SimpleRows({
  caption,
  head,
  rows,
}: {
  readonly caption: string;
  readonly head: readonly string[];
  readonly rows: readonly (readonly ReactNode[])[];
}) {
  const { t } = useTranslation();
  return (
    <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
      <table className={styles.table} data-stack>
        <caption className="ux-sr-only">{caption}</caption>
        <thead>
          <tr>
            {head.map((cell, index) => (
              <th key={index} scope="col">
                {cell}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              {row.map((cell, column) =>
                column === 0 ? (
                  <th key={column} scope="row">
                    {cell}
                  </th>
                ) : (
                  <td key={column} data-k={head[column]}>
                    {cell}
                  </td>
                ),
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── breakdown ────────────────────────────────────────────────────────────────────────────────────────────────────

function Breakdown({ bench }: { readonly bench: Benchmark }) {
  if (bench.id === 'agentdojo') {
    return <AgentDojoBreakdown bench={bench} />;
  }
  if (bench.id === 'injecagent') {
    return <InjecAgentBreakdown bench={bench} />;
  }
  return <PromptfooBreakdown bench={bench} />;
}

function AgentDojoBreakdown({ bench }: { readonly bench: AgentDojoBench }) {
  const { t, i18n } = useTranslation();
  const label = useLabel(bench);
  const n = (value: number) => formatNumber(value, i18n.language);
  const share = (value: BenchShare | null, strong = false) => (
    <ShareCell share={value} bench={bench.id} strong={strong} />
  );
  return (
    <>
      <Card title={t('ux.bench.ad.envTitle')} sub={t('ux.bench.ad.envSub')} flush>
        <SimpleRows
          caption={t('ux.bench.ad.envTitle')}
          head={[t('ux.bench.ad.env'), t('ux.bench.col.unprotected'), label('S-1a'), label('S-1b')]}
          rows={bench.breakdown.environments.map((row) => [
            <code key="s" className={styles.code}>
              {breakable(row.suite)}
            </code>,
            share(row.unprotected),
            share(row['S-1a'], true),
            share(row['S-1b'], true),
          ])}
        />
      </Card>
      <Card title={t('ux.bench.ad.benignTitle')} sub={t('ux.bench.ad.benignSub')} flush>
        <SimpleRows
          caption={t('ux.bench.ad.benignTitle')}
          head={[t('ux.bench.ad.env'), t('ux.bench.col.unprotected'), label('S-1a'), label('S-1b')]}
          rows={bench.breakdown.environments.map((row) => [
            <code key="s" className={styles.code}>
              {breakable(row.suite)}
            </code>,
            share(row.benign.unprotected),
            share(row.benign['S-1a'], true),
            share(row.benign['S-1b'], true),
          ])}
        />
      </Card>
      {Object.entries(bench.breakdown.injectionTasks).map(([test, rows]) => (
        <Card
          key={test}
          title={t('ux.bench.ad.injTitle', { test: label(test) })}
          sub={t('ux.bench.ad.injSub')}
          flush
        >
          <SimpleRows
            caption={t('ux.bench.ad.injTitle', { test: label(test) })}
            head={[
              t('ux.bench.ad.injTask'),
              t('ux.bench.ad.cases'),
              t('ux.bench.ad.succeeded'),
              t('ux.bench.ad.executed'),
            ]}
            rows={rows.map((row) => [
              <span key="n" className={styles.share}>
                <code className={styles.code}>{breakable(`${row.suite} · ${row.injectionTask}`)}</code>
                {row.textOnly ? <Badge tone="line">{t('ux.bench.ad.textOnly')}</Badge> : null}
              </span>,
              n(row.cases),
              n(row.succeeded),
              n(row.executed),
            ])}
          />
        </Card>
      ))}
    </>
  );
}

function InjecAgentBreakdown({ bench }: { readonly bench: InjecAgentBench }) {
  const { t } = useTranslation();
  return (
    <>
      {bench.breakdown.settings.map((setting) => {
        const fields = Object.keys(setting.official.unprotected).filter((field) => field !== '#Test Case');
        return (
          <Card
            key={setting.setting}
            title={t('ux.bench.inj.officialTitle', { setting: setting.setting })}
            sub={t('ux.bench.inj.officialSub')}
            flush
          >
            <SimpleRows
              caption={t('ux.bench.inj.officialTitle', { setting: setting.setting })}
              head={[t('ux.bench.inj.field'), t('ux.bench.col.unprotected'), t('ux.bench.col.protected')]}
              rows={[
                ...fields.map((field) => [
                  field,
                  String(setting.official.unprotected[field] ?? '—'),
                  <b key="p">{String(setting.official.protected[field] ?? '—')}</b>,
                ]),
                [
                  t('ux.bench.inj.directHarm'),
                  <ShareCell key="u" share={setting.directHarm.unprotected} bench={bench.id} />,
                  <ShareCell key="p" share={setting.directHarm.protected} bench={bench.id} strong />,
                ],
                [
                  t('ux.bench.inj.dataStealing'),
                  <ShareCell key="u" share={setting.dataStealingStep1.unprotected} bench={bench.id} />,
                  <ShareCell key="p" share={setting.dataStealingStep1.protected} bench={bench.id} strong />,
                ],
              ]}
            />
          </Card>
        );
      })}
    </>
  );
}

function PromptfooBreakdown({ bench }: { readonly bench: PromptfooBench }) {
  const { t } = useTranslation();
  const section = (key: 'plugins' | 'strategies' | 'categories', rows: readonly PromptfooRow[]) => (
    <Card key={key} title={t(`ux.bench.pf.${key}`)} sub={t('ux.bench.pf.sectionSub')} flush>
      <SimpleRows
        caption={t(`ux.bench.pf.${key}`)}
        head={[t('ux.bench.pf.name'), t('ux.bench.col.unprotected'), t('ux.bench.col.protected')]}
        rows={rows.map((row) => [
          <span key="n" className={styles.share}>
            <code className={styles.code}>{breakable(row.name)}</code>
            {row.notGenerated ? (
              <span className={styles.shareSub}>
                {t('ux.bench.pf.notGenerated', { names: row.notGenerated.join(', ') })}
              </span>
            ) : null}
          </span>,
          <ShareCell key="u" share={row.unprotected} bench={bench.id} />,
          <ShareCell key="p" share={row.protected} bench={bench.id} strong />,
        ])}
      />
    </Card>
  );
  return (
    <>
      {section('plugins', bench.breakdown.plugins)}
      {section('strategies', bench.breakdown.strategies)}
      {section('categories', bench.breakdown.categories)}
    </>
  );
}

// ── variants ─────────────────────────────────────────────────────────────────────────────────────────────────────

function Variants({ bench }: { readonly bench: Benchmark }) {
  if (bench.id === 'agentdojo') {
    return <AgentDojoVariants bench={bench} />;
  }
  if (bench.id === 'injecagent') {
    return <InjecAgentVariants bench={bench} />;
  }
  return null;
}

function AgentDojoVariants({ bench }: { readonly bench: AgentDojoBench }) {
  const { t, i18n } = useTranslation();
  const label = useLabel(bench);
  const n = (value: number) => formatNumber(value, i18n.language);
  const share = (value: BenchShare | null, strong = false) => (
    <ShareCell share={value} bench={bench.id} strong={strong} />
  );
  const v = bench.variants;
  const test = (id: string) => bench.tests.find((item) => item.id === id) ?? null;
  return (
    <>
      <Card title={t('ux.bench.ad.ownersTitle')} sub={t('ux.bench.ad.ownersSub')} flush>
        <SimpleRows
          caption={t('ux.bench.ad.ownersTitle')}
          head={[
            t('ux.bench.col.test'),
            t('ux.bench.ad.ownerCol'),
            t('ux.bench.col.protected'),
            t('ux.bench.col.paired'),
          ]}
          rows={v.owners.map((row) => [
            label(row.test),
            row.owner === 'llm' && row.asked !== undefined
              ? t('ux.bench.ad.ownerLlm', { asked: n(row.asked), approved: n(row.approved ?? 0) })
              : t(`ux.bench.ad.owner.${row.owner}`),
            share(test(row.test)?.protected ?? null, true),
            <PairedCell key="p" paired={test(row.test)?.paired ?? null} direction="lower" />,
          ])}
        />
      </Card>
      <Card title={t('ux.bench.ad.remeasureTitle')} sub={t('ux.bench.ad.remeasureSub')} flush>
        <SimpleRows
          caption={t('ux.bench.ad.remeasureTitle')}
          head={[t('ux.bench.col.test'), 'test-v1', 'test-v2', t('ux.bench.ad.againstFirst')]}
          rows={v.remeasure.map((row) => {
            const against = row.againstFirst.attack_success;
            return [
              label(row.test),
              share(test(row.test)?.protected ?? null),
              share(row.protected, true),
              against
                ? t('ux.bench.ad.againstValue', {
                    remeasured: n(against.onlyRemeasured),
                    first: n(against.onlyFirst),
                    p: formatNumber(against.p, i18n.language, 3),
                  })
                : '—',
            ];
          })}
        />
      </Card>
      <Card
        title={t('ux.bench.ad.variantsTitle')}
        sub={t('ux.bench.ad.variantsSub', {
          weak: n(v.attackVariants.weaknesses.length),
        })}
        flush
      >
        <SimpleRows
          caption={t('ux.bench.ad.variantsTitle')}
          head={[
            t('ux.bench.ad.variant'),
            t('ux.bench.ad.fallenFor'),
            t('ux.bench.col.executed'),
            t('ux.bench.ad.control'),
          ]}
          rows={[
            ...v.attackVariants.variants.map((row) => [
              <code key="v" className={styles.code}>
                {breakable(row.variant)}
              </code>,
              share(row.fallenFor, true),
              share(row.executedOnly),
              share(row.control),
            ]),
            [
              <b key="t">{t('ux.bench.ad.variantsAll')}</b>,
              share(v.attackVariants.overall.fallenFor, true),
              share(v.attackVariants.overall.executedOnly),
              share(v.attackVariants.overall.control),
            ],
          ]}
        />
      </Card>
      <Card title={t('ux.bench.ad.warmTitle')} sub={t('ux.bench.ad.warmSub', { n: n(v.warm.pairs) })} flush>
        <SimpleRows
          caption={t('ux.bench.ad.warmTitle')}
          head={[
            t('ux.bench.col.metricShort'),
            t('ux.bench.ad.cold'),
            t('ux.bench.ad.warm'),
            t('ux.bench.col.paired'),
          ]}
          rows={[
            [
              'Targeted ASR',
              share(v.warm.cold),
              share(v.warm.warm, true),
              <WarmCell key="p" paired={v.warm.paired} />,
            ],
            [
              'Benign Utility',
              share(v.warm.benignCold),
              share(v.warm.benignWarm, true),
              <WarmCell key="p" paired={v.warm.benignPaired} />,
            ],
          ]}
        />
      </Card>
    </>
  );
}

/** A warm-against-cold pair in plain words: how many held only in each state, and the exact p. */
function WarmCell({ paired }: { readonly paired: WarmPaired }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  return (
    <span className={styles.share}>
      <span className={styles.shareValue}>
        {t('ux.bench.ad.warmPaired', { warm: n(paired.onlyWarm), cold: n(paired.onlyCold) })}
      </span>
      <span className={styles.shareSub}>{`p ${pText(paired.p, i18n.language)}`}</span>
    </span>
  );
}

function InjecAgentVariants({ bench }: { readonly bench: InjecAgentBench }) {
  const { t, i18n } = useTranslation();
  const p = (value: number) => formatNumber(value, i18n.language, 3);
  return (
    <Card
      title={t('ux.bench.inj.evidenceTitle')}
      sub={t('ux.bench.inj.evidenceSub')}
      actions={<OwnBadge />}
      flush
    >
      <SimpleRows
        caption={t('ux.bench.inj.evidenceTitle')}
        head={[
          t('ux.bench.inj.setting'),
          t('ux.bench.inj.measure'),
          t('ux.bench.inj.with'),
          t('ux.bench.inj.without'),
          'p',
        ]}
        rows={bench.variants.evidence.flatMap((row) => [
          [
            row.setting,
            t('ux.bench.inj.refused'),
            <ShareCell key="w" share={row.attackerCallsRefused.with} bench={bench.id} strong />,
            <ShareCell key="o" share={row.attackerCallsRefused.without} bench={bench.id} />,
            p(row.attackerCallsRefused.paired.p_exact),
          ],
          [
            row.setting,
            t('ux.bench.metric.benignCallsRefused'),
            <ShareCell key="w" share={row.benignCallsRefused.with} bench={bench.id} strong />,
            <ShareCell key="o" share={row.benignCallsRefused.without} bench={bench.id} />,
            p(row.benignCallsRefused.paired.p_exact),
          ],
        ])}
      />
    </Card>
  );
}

// ── cases ────────────────────────────────────────────────────────────────────────────────────────────────────────

function Cases({ bench }: { readonly bench: Benchmark }) {
  const { t, i18n } = useTranslation();
  const label = useLabel(bench);
  const n = (value: number) => formatNumber(value, i18n.language);
  if (bench.id === 'agentdojo') {
    return (
      <>
        {Object.entries(bench.cases).map(([test, rows]) => (
          <Card
            key={test}
            title={t('ux.bench.cases.agentdojoTitle', { test: label(test), n: n(rows.length) })}
            sub={t('ux.bench.cases.agentdojoSub')}
          >
            <ol className={styles.cases}>
              {rows.map((row) => (
                <li key={`${row.suite}-${row.userTask}-${row.injectionTask}`} className={styles.case}>
                  <span className={styles.caseHead}>
                    <code className={styles.code}>
                      {breakable(`${row.suite} · ${row.userTask} × ${row.injectionTask}`)}
                    </code>
                    {row.executed ? null : <Badge tone="line">{t('ux.bench.cases.notExecuted')}</Badge>}
                    {row.textOnly ? <Badge tone="line">{t('ux.bench.ad.textOnly')}</Badge> : null}
                  </span>
                  <span className={styles.caseLine}>
                    <span className={styles.caseKey}>{t('ux.bench.cases.request')}</span>
                    <span lang="en">{row.userRequest}</span>
                  </span>
                  <span className={styles.caseLine}>
                    <span className={styles.caseKey}>{t('ux.bench.cases.goal')}</span>
                    <span lang="en">{row.attackGoal}</span>
                  </span>
                </li>
              ))}
            </ol>
          </Card>
        ))}
      </>
    );
  }
  if (bench.id === 'injecagent') {
    const rows = bench.cases.protected;
    return (
      <Card
        title={t('ux.bench.cases.injecagentTitle', { n: n(rows.length) })}
        sub={t('ux.bench.cases.injecagentSub')}
        flush
      >
        <SimpleRows
          caption={t('ux.bench.cases.injecagentTitle', { n: n(rows.length) })}
          head={[
            t('ux.bench.inj.setting'),
            t('ux.bench.cases.attackType'),
            t('ux.bench.cases.userTool'),
            t('ux.bench.cases.attackerTools'),
          ]}
          rows={rows.map((row) => [
            row.setting,
            row.attackType,
            <code key="u" className={styles.code}>
              {breakable(row.userTool)}
            </code>,
            <code key="a" className={styles.code}>
              {row.attackerTools.map((tool, index) => (
                <Fragment key={index}>
                  {index > 0 ? ', ' : null}
                  {breakable(tool)}
                </Fragment>
              ))}
            </code>,
          ])}
        />
      </Card>
    );
  }
  const list = (key: 'fixed' | 'broken') => (
    <Card
      key={key}
      title={t(`ux.bench.cases.${key}`, { n: n(bench.cases[key].length) })}
      sub={t('ux.bench.cases.promptfooSub')}
      flush
    >
      <SimpleRows
        caption={t(`ux.bench.cases.${key}`, { n: n(bench.cases[key].length) })}
        head={[t('ux.bench.cases.test'), t('ux.bench.pf.name'), t('ux.bench.cases.strategy')]}
        rows={bench.cases[key].map((row) => [
          `#${row.test}`,
          <code key="p" className={styles.code}>
            {breakable(row.plugin)}
          </code>,
          <code key="s" className={styles.code}>
            {breakable(row.strategy)}
          </code>,
        ])}
      />
    </Card>
  );
  return (
    <>
      <Note>{t('ux.bench.cases.promptfooNote')}</Note>
      <div className={styles.split}>
        {list('broken')}
        {list('fixed')}
      </div>
    </>
  );
}

// ── settings ─────────────────────────────────────────────────────────────────────────────────────────────────────

function Settings({ bundle, bench }: { readonly bundle: Bundle; readonly bench: Benchmark }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const models = bundle.program.models;
  const freezes = bundle.freezes.filter((freeze) => bench.settings.freezes.includes(freeze.id));
  const specific =
    bench.id === 'agentdojo'
      ? [
          {
            label: t('ux.bench.set.attack'),
            value: <code className={styles.code}>{breakable(bench.settings.attack)}</code>,
          },
          {
            label: t('ux.bench.set.split'),
            value: (
              <code className={styles.code}>
                {breakable(`${bench.settings.split.file} · ${bench.settings.split.part}`)}
              </code>
            ),
          },
          {
            label: t('ux.bench.set.owner'),
            value: <code className={styles.code}>{breakable(models.owner)}</code>,
          },
        ]
      : bench.id === 'injecagent'
        ? [
            {
              label: t('ux.bench.set.firstStep'),
              value: t(bench.settings.firstStepOnly ? 'ux.bench.set.yes' : 'ux.bench.set.no'),
            },
            {
              label: t('ux.bench.set.benignSample'),
              value: t('ux.bench.set.benignSampleValue', { n: n(bench.settings.benignCallSample) }),
            },
            {
              label: t('ux.bench.set.seed'),
              value: <code className={styles.code}>{breakable(bench.settings.seed)}</code>,
            },
            {
              label: t('ux.bench.set.reused'),
              value: <code className={styles.code}>{breakable(bench.settings.reusedOutputsFrom)}</code>,
            },
          ]
        : [
            {
              label: t('ux.bench.set.preset'),
              value: <code className={styles.code}>{breakable(bench.settings.preset)}</code>,
            },
            {
              label: t('ux.bench.set.casesPlugins'),
              value: t('ux.bench.set.casesPluginsValue', {
                cases: n(bench.settings.cases),
                plugins: n(bench.settings.plugins),
              }),
            },
            { label: t('ux.bench.set.generation'), value: t('ux.bench.set.generationValue') },
          ];
  return (
    <div className={styles.split}>
      <Card title={t('ux.bench.set.title')}>
        <KeyValue
          items={[
            {
              label: t('ux.bench.set.version'),
              value: <code className={styles.code}>{breakable(bench.version)}</code>,
            },
            ...specific,
            {
              label: t('ux.bench.strip.victim'),
              value: <code className={styles.code}>{breakable(models.victim)}</code>,
            },
            {
              label: t('ux.bench.strip.judges'),
              value: (
                <span className={styles.models}>
                  <code className={styles.code}>{breakable(models.layer1)}</code>
                  <code className={styles.code}>{breakable(models.layer2)}</code>
                </span>
              ),
            },
            {
              label: t('ux.bench.set.freezes'),
              value: (
                <span className={styles.chips}>
                  {freezes.map((freeze) => (
                    <CodeChip key={freeze.id} value={`${freeze.id} ${freeze.sha256.slice(0, 8)}`} />
                  ))}
                </span>
              ),
            },
            {
              label: t('ux.bench.set.frozenAt'),
              value: freezes.map((freeze) => `${freeze.id} ${formatUtc(freeze.frozenAt)}`).join(' · '),
            },
          ]}
        />
      </Card>
      <Card title={t('ux.bench.set.cost')}>
        {bench.cost.length === 0 ? (
          <p className={styles.para}>{t('ux.bench.set.noCost')}</p>
        ) : (
          <ul className={styles.facts}>
            {bench.cost.map((cost) => (
              <li key={cost.source}>
                <b>{`$${formatNumber(cost.usd, i18n.language, 2)}`}</b> {words(cost.label, i18n.language)}
                <span className={styles.source}>
                  {t('ux.bench.limits.source', { source: words(cost.sourceLabel, i18n.language) })}
                </span>
              </li>
            ))}
          </ul>
        )}
        <p className={styles.para}>
          {t('ux.bench.set.programSpend', { usd: formatNumber(bundle.program.spendUsd, i18n.language, 2) })}
        </p>
      </Card>
    </div>
  );
}
