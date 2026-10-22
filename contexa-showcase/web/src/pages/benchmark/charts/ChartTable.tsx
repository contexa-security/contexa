import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import styles from './Charts.module.css';

interface ChartTableProps {
  readonly head: readonly string[];
  readonly rows: readonly { readonly key: string; readonly cells: readonly ReactNode[] }[];
}

/** A chart's values as a table behind "show as a table": the chart's text alternative, the same values it draws. */
export function ChartTable({ head, rows }: ChartTableProps) {
  const { t } = useTranslation();
  return (
    <details className={styles.tableBox}>
      <summary className={styles.tableToggle}>{t('bench.chart.table')}</summary>
      {/* A table wider than a phone slides inside its own region, which takes the focus for the keyboard. */}
      <div className={styles.tableScroll} role="region" aria-label={t('bench.chart.table')} tabIndex={0}>
        <table className={styles.table}>
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
            {rows.map((row) => (
              <tr key={row.key} data-row={row.key}>
                {row.cells.map((cell, index) =>
                  index === 0 ? (
                    <th key={index} scope="row">
                      {cell}
                    </th>
                  ) : (
                    <td key={index}>{cell}</td>
                  ),
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
