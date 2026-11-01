import { useQueries } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import type { DecisionAnatomyView } from '../../../api/anatomy';
import { getJson } from '../../../api/http';
import { useAnatomy } from '../../../api/anatomy';
import { useMeasuredCase } from '../../../api/measured';
import { formatDuration, formatNumber, formatUtc, localTime } from '../../format';
import { decisionOf, existingStops, useRunLog, useScenarioTitle, type LogRow, type RunSource } from '../../runs/runLog';
import { CONTROL_TONE } from '../../simulate/controls';
import { evalOf, verdictOf } from '../../simulate/person';
import { useMedia, DRAWER_QUERY } from '../../useMedia';
import {
  Badge,
  ButtonLink,
  CodeChip,
  DataTable,
  DetailGroup,
  DetailPanel,
  Drawer,
  EmptyState,
  EvalBadge,
  Field,
  Loading,
  Note,
  PageHead,
  Select,
  TextInput,
  VerdictBadge,
  type Column,
} from '../../ui';
import sim from '../../simulate/Simulate.module.css';
import styles from './Runs.module.css';

const PAGE = 10;
const SOURCES: readonly RunSource[] = ['own', 'public', 'measured'];
const VERDICTS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK', 'NONE'] as const;
const RESULTS = ['correct', 'normal', 'afterCheck', 'partial', 'missed', 'falsePositive', 'none'] as const;
const PERIODS = { day: 86_400_000, week: 604_800_000 } as const;

/**
 * The decision log (기획안 7.2, DEC-40 · DEC-41): the visitor's own runs, the public recorded runs and the measured runs,
 * newest first, filtered by source, ground truth, decision, result, period and a search, ten a page. The row chosen opens
 * beside the list (a drawer on a phone) with its request, Contexa's decision and the five controls' exports. Every value
 * is the portal's record; the filters live in the address.
 */
export default function RunsPage() {
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const log = useRunLog();
  const titleOf = useScenarioTitle();
  const narrow = useMedia(DRAWER_QUERY);
  const set = (next: Readonly<Record<string, string | null>>, keepPage = false) => {
    const query = new URLSearchParams(params);
    Object.entries(next).forEach(([key, value]) => (value === null || value === '' ? query.delete(key) : query.set(key, value)));
    if (!keepPage) {
      query.delete('page');
    }
    setParams(query, { replace: true });
  };
  const source = params.get('source');
  const kind = params.get('kind');
  const verdict = params.get('verdict');
  const result = params.get('result');
  const period = params.get('period') as keyof typeof PERIODS | null;
  const search = (params.get('q') ?? params.get('pair') ?? '').trim().toLowerCase();
  const language = i18n.language;
  // The period is counted from when the log was opened (a render must not read the clock).
  const [now] = useState(() => Date.now());
  const rows = log.rows.filter((row) => {
    const decided = verdictOf(decisionOf(row.score).action);
    const graded = evalOf(row.score?.business.D?.result) ?? 'none';
    const truth = row.score?.truth.classification ?? null;
    return (
      (!source || row.source === source) &&
      (!kind || (kind === 'THREAT' ? truth === 'THREAT' : truth === 'NORMAL')) &&
      (!verdict || decided === verdict) &&
      (!result || graded === result) &&
      (!period || (row.at !== null && now - Date.parse(row.at) <= PERIODS[period])) &&
      (!search ||
        row.runId.toLowerCase().includes(search) ||
        row.scenarioKey.toLowerCase().includes(search) ||
        titleOf(row.scenarioKey, row.score?.title, language).toLowerCase().includes(search))
    );
  });
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const page = Math.min(pages, Math.max(1, Number(params.get('page')) || 1));
  const shown = rows.slice((page - 1) * PAGE, page * PAGE);
  const chosenId = params.get('run');
  const chosen = log.rows.find((row) => row.runId === chosenId) ?? null;
  const times = useDecisionTimes(shown);
  const filtered = Boolean(source || kind || verdict || result || period || search);

  const columns: Column<LogRow>[] = [
    {
      key: 'at',
      header: t('ux.runs.col.at'),
      render: (row) => (
        <span className={styles.at} title={row.at ? localTime(row.at, language) : undefined}>
          {row.at ? formatUtc(row.at).slice(5) : '—'}
        </span>
      ),
    },
    {
      key: 'scenario',
      header: t('ux.runs.col.scenario'),
      strong: true,
      render: (row) => (
        <Link
          to={`?${withParam(params, 'run', row.runId)}`}
          replace
          className={styles.rowLink}
          aria-current={row.runId === chosenId ? 'true' : undefined}
        >
          <span className={styles.rowTitle}>{titleOf(row.scenarioKey, row.score?.title, language)}</span>
          <span className={styles.rowSub}>
            {row.scenarioKey} · {row.runId}
            {row.lab ? ` · ${t('ux.runs.lab')}` : ''}
          </span>
          <span className={styles.rowSource}>{t(`ux.runs.source.${row.source}`)}</span>
        </Link>
      ),
    },
    {
      key: 'verdict',
      header: t('ux.runs.col.verdict'),
      render: (row) => (row.score ? <VerdictBadge verdict={verdictOf(decisionOf(row.score).action)} /> : '…'),
    },
    {
      key: 'result',
      header: t('ux.runs.col.result'),
      render: (row) => <Graded row={row} />,
    },
    {
      key: 'existing',
      header: t('ux.runs.col.existing'),
      numeric: true,
      render: (row) => {
        const stops = existingStops(row.score);
        return stops === null ? '…' : `${stops} / 4`;
      },
    },
    {
      key: 'time',
      header: t('ux.runs.col.time'),
      numeric: true,
      render: (row) => {
        const ms = times.get(row.runId);
        return ms === undefined ? '…' : ms === null ? '—' : t('ux.time.seconds', { value: formatDuration(ms, language) });
      },
    },
  ];

  // With the chosen run beside the list, or below 1024 wide, the list keeps three columns: the decision and the result
  // share a cell, and the existing controls and the decision time are read in the panel or the drawer.
  const compact = narrow || chosen !== null;
  const shownColumns: Column<LogRow>[] = compact
    ? [
        ...columns.filter((column) => column.key === 'at' || column.key === 'scenario'),
        {
          key: 'decision',
          header: t('ux.runs.col.decision'),
          render: (row) => (
            <span className={styles.badges}>
              {row.score ? <VerdictBadge verdict={verdictOf(decisionOf(row.score).action)} /> : '…'}
              <Graded row={row} />
            </span>
          ),
        },
      ]
    : columns;
  return (
    <>
      <PageHead title={t('ux.runs.title')} desc={t('ux.runs.desc')} />
      {log.failed.length > 0 ? (
        <Note tone="warn">
          {t('ux.runs.partial', { sources: log.failed.map((failed) => t(`ux.runs.source.${failed}`)).join(' · ') })}
        </Note>
      ) : null}
      <div className={styles.layout} data-panel={(chosen && !narrow) || undefined}>
        <section className={styles.list} aria-label={t('ux.runs.title')}>
          <div className={styles.filters}>
            <FilterSelect
              label={t('ux.runs.filter.source')}
              value={source}
              options={SOURCES.map((id) => [id, t(`ux.runs.source.${id}`)] as const)}
              onChange={(value) => set({ source: value })}
            />
            <FilterSelect
              label={t('ux.runs.filter.kind')}
              value={kind}
              options={[
                ['THREAT', t('ux.runs.kind.THREAT')],
                ['NORMAL', t('ux.runs.kind.NORMAL')],
              ]}
              onChange={(value) => set({ kind: value })}
            />
            <FilterSelect
              label={t('ux.runs.filter.verdict')}
              value={verdict}
              options={VERDICTS.map((id) => [id, t(`ux.runs.verdict.${id}`)] as const)}
              onChange={(value) => set({ verdict: value })}
            />
            <FilterSelect
              label={t('ux.runs.filter.result')}
              value={result}
              options={RESULTS.map((id) => [id, t(`ux.runs.result.${id}`)] as const)}
              onChange={(value) => set({ result: value })}
            />
            <FilterSelect
              label={t('ux.runs.filter.period')}
              value={period}
              options={[
                ['day', t('ux.runs.period.day')],
                ['week', t('ux.runs.period.week')],
              ]}
              onChange={(value) => set({ period: value })}
            />
            <Field label={t('ux.runs.filter.search')}>
              {(props) => (
                <TextInput
                  {...props}
                  compact
                  type="search"
                  placeholder={t('ux.runs.searchHint')}
                  value={params.get('q') ?? params.get('pair') ?? ''}
                  onChange={(event) => set({ q: event.target.value, pair: null })}
                />
              )}
            </Field>
          </div>
          {log.pending ? (
            <Loading rows={6} />
          ) : rows.length === 0 ? (
            <EmptyState
              action={
                filtered ? (
                  <ButtonLink to="/runs" variant="secondary">
                    {t('ux.runs.clear')}
                  </ButtonLink>
                ) : null
              }
            >
              {t(filtered ? 'ux.runs.emptyFiltered' : 'ux.runs.empty')}
            </EmptyState>
          ) : (
            <>
              <DataTable
                caption={t('ux.runs.title')}
                columns={shownColumns}
                rows={shown}
                rowKey={(row) => row.runId}
                {...(chosenId ? { selected: chosenId } : {})}
                stack
              />
              <nav className={styles.pager} aria-label={t('ux.runs.pages')}>
                <span>
                  {t('ux.runs.count', {
                    total: formatNumber(rows.length, language),
                    from: formatNumber((page - 1) * PAGE + 1, language),
                    to: formatNumber(Math.min(rows.length, page * PAGE), language),
                  })}
                </span>
                <span className={styles.pages}>
                  {Array.from({ length: pages }, (_, index) => index + 1).map((number) => (
                    <Link
                      key={number}
                      to={`?${withParam(params, 'page', String(number))}`}
                      replace
                      className={styles.page}
                      aria-current={number === page ? 'page' : undefined}
                      aria-label={t('ux.runs.pageLabel', { n: number })}
                    >
                      {number}
                    </Link>
                  ))}
                </span>
              </nav>
            </>
          )}
        </section>
        {chosen && !narrow ? <RunPanel row={chosen} onClose={() => set({ run: null }, true)} /> : null}
      </div>
      {narrow ? (
        // The drawer's own head and foot hold the run's title and actions (one close button).
        <Drawer
          open={chosen !== null}
          onClose={() => set({ run: null }, true)}
          title={chosen ? <RunTitle row={chosen} /> : ''}
          footer={chosen ? <RunActions row={chosen} /> : null}
        >
          {chosen ? (
            <div className={styles.drawerGroups}>
              <RunBody row={chosen} />
            </div>
          ) : null}
        </Drawer>
      ) : null}
    </>
  );
}

function withParam(params: URLSearchParams, key: string, value: string): string {
  const next = new URLSearchParams(params);
  next.set(key, value);
  return next.toString();
}

function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  readonly label: string;
  readonly value: string | null;
  readonly options: readonly (readonly [string, string])[];
  readonly onChange: (value: string | null) => void;
}) {
  const { t } = useTranslation();
  return (
    <Field label={label}>
      {(props) => (
        <Select {...props} compact value={value ?? ''} onChange={(event) => onChange(event.target.value || null)}>
          <option value="">{t('ux.runs.all')}</option>
          {options.map(([id, name]) => (
            <option key={id} value={id}>
              {name}
            </option>
          ))}
        </Select>
      )}
    </Field>
  );
}

/** The decision time of the rows on view (DEC-41): the deciding request's analysis; null when it has none. */
function useDecisionTimes(rows: readonly LogRow[]): ReadonlyMap<string, number | null> {
  const asked = rows.filter((row) => row.score !== null);
  const answers = useQueries({
    queries: asked.map((row) => {
      const step = decisionOf(row.score).step;
      return {
        queryKey: ['anatomy', row.runId, step],
        queryFn: () =>
          getJson<DecisionAnatomyView>(`/api/runs/${encodeURIComponent(row.runId)}/steps/${step}/anatomy`),
        staleTime: Infinity,
        retry: false,
      };
    }),
  });
  return new Map(
    asked.flatMap((row, index) => {
      const answer = answers[index];
      if (!answer || answer.isPending) {
        return [];
      }
      return [[row.runId, answer.data?.interpretation?.timings?.totalAnalysisMs ?? null] as const];
    }),
  );
}

/** How the run was graded against its scenario's ground truth, or that it was not. */
function Graded({ row }: { readonly row: LogRow }) {
  const { t } = useTranslation();
  const graded = evalOf(row.score?.business.D?.result);
  return graded ? <EvalBadge result={graded} /> : <span className={styles.muted}>{t('ux.runs.unscored')}</span>;
}

/** The chosen run's title: its ID and its grade. */
function RunTitle({ row }: { readonly row: LogRow }) {
  const graded = evalOf(row.score?.business.D?.result);
  return (
    <span className={styles.panelTitle}>
      <span className={styles.mono}>{row.runId}</span>
      {graded ? <EvalBadge result={graded} /> : null}
    </span>
  );
}

/** The chosen run's actions: copy its ID, open its details. */
function RunActions({ row }: { readonly row: LogRow }) {
  const { t } = useTranslation();
  return (
    <>
      <CodeChip value={row.runId} copy />
      <ButtonLink to={`/runs/${encodeURIComponent(row.runId)}`} variant="primary" icon="panel-right-open">
        {t('ux.runs.open')}
      </ButtonLink>
    </>
  );
}

/** The row chosen beside the list on a wide screen. */
function RunPanel({ row, onClose }: { readonly row: LogRow; readonly onClose: () => void }) {
  return (
    <DetailPanel title={<RunTitle row={row} />} onClose={onClose} footer={<RunActions row={row} />}>
      <RunBody row={row} />
    </DetailPanel>
  );
}

/** The row chosen: the request, Contexa's decision with its scores and reason, and what each control let out. */
function RunBody({ row }: { readonly row: LogRow }) {
  const { t, i18n } = useTranslation();
  const titleOf = useScenarioTitle();
  const decision = decisionOf(row.score);
  const anatomy = useAnatomy(row.score ? row.runId : null, decision.step);
  const recorded = anatomy.data?.interpretation?.recorded ?? null;
  const timings = anatomy.data?.interpretation?.timings ?? null;
  const n = (value: number) => formatNumber(value, i18n.language);
  return (
    <>
      <DetailGroup title={t('ux.runs.panel.request')}>
        <dl className={styles.kv}>
          <dt>{t('ux.runs.col.scenario')}</dt>
          <dd>
            {titleOf(row.scenarioKey, row.score?.title, i18n.language)} ({row.scenarioKey})
          </dd>
          {row.sentence ? (
            <>
              <dt>{t('ux.runs.panel.situation')}</dt>
              <dd>{row.sentence[i18n.language === 'ko' ? 'ko' : 'en'] ?? row.sentence.en}</dd>
            </>
          ) : null}
          <dt>{t('ux.runs.col.source')}</dt>
          <dd>{t(`ux.runs.source.${row.source}`)}</dd>
          <dt>{t('ux.runs.col.at')}</dt>
          <dd>{row.at ? `${formatUtc(row.at)} ${t('ux.runs.utc')}` : '—'}</dd>
          {row.score && row.score.executedSteps > 1 ? (
            <>
              <dt>{t('ux.result.decidingStep')}</dt>
              <dd>{t('ux.result.decidingStepValue', { n: decision.step, total: row.score.executedSteps })}</dd>
            </>
          ) : null}
        </dl>
      </DetailGroup>
      <DetailGroup title={t('ux.runs.panel.decision')}>
        <p className={styles.decision}>
          {row.score ? <VerdictBadge verdict={verdictOf(decision.action)} /> : null}
          {recorded?.riskScore != null ? (
            <span className={styles.muted}>
              {t('ux.result.evidence.scores', {
                risk: recorded.riskScore.toFixed(2),
                confidence: recorded.confidence?.toFixed(2) ?? '—',
              })}
              {timings?.totalAnalysisMs != null
                ? ` · ${t('ux.time.seconds', { value: formatDuration(timings.totalAnalysisMs, i18n.language) })}`
                : ''}
            </span>
          ) : null}
        </p>
        {recorded?.reasoning ? (
          <p className={styles.reason} lang={recorded.reasoningCode ? undefined : 'en'}>
            {recorded.reasoningCode ? null : (
              <>
                <Badge tone="line">{t('ux.recovery.original')}</Badge>{' '}
              </>
            )}
            {recorded.reasoningCode
              ? t(`reason.canonical.${recorded.reasoningCode}`, { defaultValue: recorded.reasoning })
              : recorded.reasoning}
          </p>
        ) : null}
      </DetailGroup>
      <DetailGroup title={t('ux.runs.panel.controls')}>
        <ul className={styles.controls}>
          {(['A', 'B', 'C1', 'C2', 'D'] as const).map((control) => {
            const business = row.score?.business[control] ?? null;
            // The server's grade of each control against the ground truth: a normal run an existing control halted
            // reads as a false positive, a threat it let through as missed (the old replay's wrong mark).
            const graded = evalOf(business?.result);
            return (
              <li key={control}>
                <span className={styles.controlName}>
                  <span className={sim.swatch} data-tone={CONTROL_TONE[control]} aria-hidden="true" />
                  {t(`ux.control.short.${control}`)}
                </span>
                {business ? (
                  <span className={styles.controlBadges}>
                    {graded ? <EvalBadge result={graded} /> : null}
                    <Badge tone={business.exposedItems > 0 && row.score?.truth.classification === 'THREAT' ? 'block' : 'none'}>
                      {t('ux.runs.exported', { n: n(business.exposedItems), count: business.exposedItems })}
                    </Badge>
                  </span>
                ) : (
                  '…'
                )}
              </li>
            );
          })}
        </ul>
      </DetailGroup>
      <Measurement row={row} />
    </>
  );
}

/** The order the results of a measurement are listed in; a result the portal adds later comes last. */
const RESULT_ORDER: readonly string[] = ['STOPPED', 'PARTLY_STOPPED', 'PASSED_AFTER_CHECK', 'PASSED', 'HALTED', 'MISSED'];

/**
 * The current measurement of the run's scenario (the old replay's source line, P-8): how many runs it holds and how
 * many ended with each result, as the portal counted them, and whether this run is one of them with its start. Nothing
 * when the scenario has no run in the current measurement.
 */
function Measurement({ row }: { readonly row: LogRow }) {
  const { t, i18n } = useTranslation();
  const measured = useMeasuredCase(row.scenarioKey || null).data ?? null;
  if (!measured) {
    return null;
  }
  const n = (value: number) => formatNumber(value, i18n.language);
  const rank = (key: string) => {
    const index = RESULT_ORDER.indexOf(key);
    return index < 0 ? RESULT_ORDER.length : index;
  };
  const results = Object.entries(measured.results).sort((left, right) => rank(left[0]) - rank(right[0]));
  const mine = measured.list.find((run) => run.runId === row.runId) ?? null;
  return (
    <DetailGroup title={t('ux.runs.panel.measure')}>
      <dl className={styles.kv}>
        <dt>{t('ux.runs.measure.runs')}</dt>
        <dd>{t('ux.runs.measure.count', { count: measured.runs, n: n(measured.runs) })}</dd>
        <dt>{t('ux.runs.measure.results')}</dt>
        <dd>
          {results.length > 0
            ? results
                .map(([result, count]) =>
                  t('ux.runs.measure.result', {
                    result: t(`ux.validation.result.${result}`, { defaultValue: result }),
                    n: n(count),
                  }),
                )
                .join(' · ')
            : '—'}
        </dd>
        <dt>{t('ux.runs.measure.this')}</dt>
        <dd>
          {mine
            ? t('ux.runs.measure.in', {
                at: mine.startedAt ? `${formatUtc(mine.startedAt)} ${t('ux.runs.utc')}` : '—',
              })
            : t('ux.runs.measure.out')}
        </dd>
      </dl>
    </DetailGroup>
  );
}
