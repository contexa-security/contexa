import type { StatsView } from '../../../api/types';

/** The final decisions in the order the screens read them: allow, step-up, hold, block (기획안 7.4). */
export const ACTIONS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'] as const;
export type Action = (typeof ACTIONS)[number];

/** Runs stopped by a technical failure as a share of the runs that finished, completed or failed (DEC-64). */
export function failedShare(runs: StatsView['runs']): number | null {
  const finished = runs.completed + runs.failed;
  return finished > 0 ? runs.failed / finished : null;
}

/** The completed runs the operator started (measurements and checks): every completed run that is not a visitor's. */
export function operatorRuns(runs: StatsView['runs']): number {
  return Math.max(0, runs.completed - runs.live);
}

/** The engine's decisions, the server's own sum when it sends one (older answers lack it). */
export function decisionsOf(stats: StatsView): number {
  return stats.engineDecisions ?? ACTIONS.reduce((sum, action) => sum + (stats.engineActions[action] ?? 0), 0);
}

/** The end of the latency axis: the p95 rounded up to whole five seconds, at least five. */
export function axisEnd(p95Ms: number): number {
  return Math.max(5, Math.ceil(p95Ms / 5000) * 5);
}
