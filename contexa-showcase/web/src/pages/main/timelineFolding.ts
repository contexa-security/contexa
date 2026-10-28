import type { AgentRunStep } from '../../api/agentCase';
import type { LiveLayer } from '../../api/types';

/** One request of the work as a timeline shows it: from the stored run, or from the live run while it works. */
export interface TimelineRow {
  readonly stepNo: number;
  readonly layers: Readonly<Record<string, LiveLayer>>;
  /** The stored step; null while the run is live and nothing is stored yet. */
  readonly step: AgentRunStep | null;
}

export type Folded =
  | { readonly kind: 'row'; readonly row: TimelineRow }
  | { readonly kind: 'group'; readonly rows: readonly TimelineRow[] };

/** The fewest alike requests in a row that are folded into one group (a burst, not a repeated read or two). */
export const FOLD_AT = 5;

/** What makes two requests "alike": the same address and the same answer of every control. */
function sameness(row: TimelineRow): string | null {
  const step = row.step;
  if (!step) {
    return null;
  }
  const answers = Object.keys(step.outcomes)
    .sort()
    .map((control) => `${control}:${step.outcomes[control]?.outcome}/${step.outcomes[control]?.rule ?? ''}`)
    .join(';');
  return `${step.path}|${answers}`;
}

/**
 * The timeline's rows with every burst folded (docs/agent Agent중심-화면 AS-9): consecutive requests with the same address
 * and the same answers at every control, {@link FOLD_AT} or more, become one group; the rest stay rows. A live run has no
 * stored steps, so nothing of it is folded.
 */
export function foldRows(rows: readonly TimelineRow[]): readonly Folded[] {
  const folded: Folded[] = [];
  let at = 0;
  while (at < rows.length) {
    const key = sameness(rows[at] as TimelineRow);
    let end = at + 1;
    while (key !== null && end < rows.length && sameness(rows[end] as TimelineRow) === key) {
      end += 1;
    }
    if (key !== null && end - at >= FOLD_AT) {
      folded.push({ kind: 'group', rows: rows.slice(at, end) });
    } else {
      for (let index = at; index < end; index += 1) {
        folded.push({ kind: 'row', row: rows[index] as TimelineRow });
      }
    }
    at = end;
  }
  return folded;
}

/** What a folded group stands for: its requests, those that have a verdict of their own, and their model calls. */
export function groupFacts(rows: readonly TimelineRow[]): {
  readonly count: number;
  readonly withVerdict: number;
  readonly modelCalls: number;
} {
  let withVerdict = 0;
  let modelCalls = 0;
  for (const row of rows) {
    const decision = row.step?.decision;
    if (decision?.final_action) {
      withVerdict += 1;
    }
    modelCalls += Number(decision?.model_calls ?? 0);
  }
  return { count: rows.length, withVerdict, modelCalls };
}
