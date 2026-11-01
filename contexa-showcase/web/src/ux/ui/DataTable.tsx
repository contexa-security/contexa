import type { ReactNode } from 'react';
import styles from './DataTable.module.css';

export interface Column<Row> {
  readonly key: string;
  readonly header: string;
  /** Numbers and times: right-aligned, fixed-width figures, never wrapped. */
  readonly numeric?: boolean;
  /** The row's name: the strongest text of the row. */
  readonly strong?: boolean;
  /** A sentence, not a name: the strong cell wraps instead of holding one line (the privacy table's items). */
  readonly wrap?: boolean;
  readonly render: (row: Row) => ReactNode;
}

interface DataTableProps<Row> {
  /** The table's name for assistive technology (shown to no one else; the card title says it). */
  readonly caption: string;
  readonly columns: readonly Column<Row>[];
  readonly rows: readonly Row[];
  readonly rowKey: (row: Row) => string;
  /** The row open in the detail panel: blue background with a blue stripe, announced as the current row. */
  readonly selected?: string;
  /** Contexa's own row of a comparison: the gold stripe. */
  readonly highlighted?: (row: Row) => boolean;
  /**
   * A list table (decision log, cited facts) stacks into one card per row on a phone, each value under its column's
   * name; a figure table scrolls sideways inside its card with the first column held.
   */
  readonly stack?: boolean;
}

/** Head 40 (13/600), rows 48, cells padded 16 (기획안 5.2). */
export function DataTable<Row>({
  caption,
  columns,
  rows,
  rowKey,
  selected,
  highlighted,
  stack = false,
}: DataTableProps<Row>) {
  return (
    // A table wider than its card scrolls sideways; the scrolling box takes the keyboard focus so it can be scrolled
    // without a pointer (axe scrollable-region-focusable).
    <div className={styles.scroll} role="region" aria-label={caption} tabIndex={0}>
      <table className={styles.table} data-stack={stack || undefined}>
        <caption className="ux-sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} scope="col" data-numeric={column.numeric || undefined}>
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = rowKey(row);
            return (
              <tr
                key={key}
                aria-current={selected === key ? 'true' : undefined}
                data-highlight={highlighted?.(row) || undefined}
              >
                {columns.map((column) => (
                  <td
                    key={column.key}
                    data-k={column.header}
                    data-numeric={column.numeric || undefined}
                    data-strong={column.strong || undefined}
                    data-wrap={column.wrap || undefined}
                  >
                    {column.render(row)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
