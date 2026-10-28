import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { BenchmarkCase, BenchmarkView } from '../../../api/benchmark';
import { useUrlModal } from '../../../components/common/useUrlModal';
import { CONTROL_ORDER } from '../../../domain/verdict';
import { controlName } from '../benchData';
import { BENCH_MODALS } from '../benchPlace';
import { CellLegend, RunCells, type RunCell } from './RunCells';
import { useNarrow } from '../../../hooks/useNarrow';
import styles from './Charts.module.css';

interface Group {
  readonly key: string;
  readonly title: string;
  readonly rows: readonly BenchmarkCase[];
}

/** The runs of a case for one approach, in the server's run order. */
function runsOf(row: BenchmarkCase, control: string): RunCell[] {
  return Object.entries(row.runResults ?? {}).map(([runId, results]) => ({
    runId,
    result: results[control] ?? 'NOT_SCORED',
  }));
}

/** The results the map's cells can show, in the legend's order (B-01: the case list has its own legend). */
const LEGEND = ['STOPPED', 'PARTLY_STOPPED', 'MISSED', 'PASSED', 'PASSED_AFTER_CHECK', 'HALTED'] as const;

interface CaseMapProps {
  readonly view: BenchmarkView;
  readonly nameOf: (row: BenchmarkCase) => string;
}

/**
 * B-3 of docs/showcase/벤치마크-구현계획.md: every situation against the five approaches, a cell per run with its
 * result, grouped by the server's named groups and then by kind. The case's name opens its window; a cell opens its
 * run. At phone width each situation is a card with a line of cells per approach.
 */
export function CaseMap({ view, nameOf }: CaseMapProps) {
  const { t } = useTranslation();
  const narrow = useNarrow();
  const [wrongOnly, setWrongOnly] = useState(false);
  const benchCase = useUrlModal(BENCH_MODALS.benchCase, ['case']);
  const byKey = new Map(view.cases.map((row) => [row.key, row]));
  const named = new Set(view.suites.flatMap((suite) => suite.cases));
  const groups: Group[] = [
    ...view.suites.map((suite) => ({
      key: suite.suite,
      title: t(`bench.chart.map.suite.${suite.suite}`, {
        defaultValue: t(`bench.r7.suite.${suite.suite}`, { defaultValue: suite.suite }),
      }),
      rows: suite.cases.flatMap((key) => (byKey.has(key) ? [byKey.get(key) as BenchmarkCase] : [])),
    })),
    ...(['THREAT', 'NORMAL', 'UNCERTAIN'] as const).map((kind) => ({
      key: kind,
      title: t(`bench.chart.map.kind.${kind}`),
      rows: view.cases.filter((row) => row.classification === kind && !named.has(row.key)),
    })),
  ]
    .map((group) => ({ ...group, rows: group.rows.filter((row) => !wrongOnly || row.contexaWrong) }))
    .filter((group) => group.rows.length > 0)
    // The situations the rules were not written for first (the proof), then the others in the server's order.
    .sort((a, b) => Number(b.key === 'RULE_BLIND') - Number(a.key === 'RULE_BLIND'));
  const answer = (row: BenchmarkCase) => (
    <span className={styles.answer} data-answer={row.classification}>
      {t(`bench.chart.map.answer.${row.classification}`, { defaultValue: row.classification })}
    </span>
  );
  const name = (row: BenchmarkCase) => (
    <button type="button" className={styles.caseName} onClick={() => benchCase.show({ case: row.key })}>
      {nameOf(row)}
    </button>
  );
  return (
    <div className={styles.map} data-chart="map">
      <label className={styles.filter}>
        <input type="checkbox" checked={wrongOnly} onChange={(event) => setWrongOnly(event.target.checked)} />
        {t('bench.chart.map.wrongOnly')}
      </label>
      <CellLegend results={view.caseCounts.UNCERTAIN > 0 ? [...LEGEND, 'NOT_SCORED'] : LEGEND} />
      {groups.map((group, index) => (
        <details key={group.key} className={styles.mapGroup} open={index === 0} data-count="exempt">
          <summary className={styles.mapSummary}>{group.title}</summary>
          <section key={group.key} className={styles.mapGroup} aria-label={group.title} data-count="exempt">
            {narrow ? (
              <ul className={styles.cards}>
                {group.rows.map((row) => (
                  <li key={row.key} className={styles.card} data-case={row.key}>
                    {name(row)}
                    {answer(row)}
                    {CONTROL_ORDER.map((control) => (
                      <div key={control} className={styles.mapCardLine}>
                        <span className={styles.cardLabel}>{controlName(t, control)}</span>
                        <RunCells
                          runs={runsOf(row, control)}
                          label={t('bench.chart.map.cells', {
                            name: nameOf(row),
                            approach: controlName(t, control),
                          })}
                        />
                      </div>
                    ))}
                  </li>
                ))}
              </ul>
            ) : (
              <div className={styles.mapGrid} role="table" aria-label={group.title}>
                <div className={styles.mapRow} role="row">
                  <span role="columnheader" className={styles.mapHead}>
                    {t('bench.chart.map.case')}
                  </span>
                  {CONTROL_ORDER.map((control) => (
                    <span
                      key={control}
                      role="columnheader"
                      className={styles.mapHead}
                      data-contexa={control === 'D' || undefined}
                    >
                      {controlName(t, control)}
                    </span>
                  ))}
                </div>
                {group.rows.map((row) => (
                  <div key={row.key} className={styles.mapRow} role="row" data-case={row.key}>
                    <span role="rowheader" className={styles.mapCase}>
                      {name(row)}
                      {answer(row)}
                    </span>
                    {CONTROL_ORDER.map((control) => (
                      <span
                        key={control}
                        role="cell"
                        className={styles.mapCell}
                        data-contexa={control === 'D' || undefined}
                      >
                        <RunCells
                          runs={runsOf(row, control)}
                          label={t('bench.chart.map.cells', {
                            name: nameOf(row),
                            approach: controlName(t, control),
                          })}
                          compact
                        />
                      </span>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </section>
        </details>
      ))}
    </div>
  );
}
