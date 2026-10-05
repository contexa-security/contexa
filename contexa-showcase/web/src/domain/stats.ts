import type { StatsView } from '../api/types';

export type EngineAction = keyof StatsView['engineActions'];

/** The engine's decisions in the order the mix bar shows them. */
export const ENGINE_ACTIONS: readonly EngineAction[] = ['ALLOW', 'CHALLENGE', 'BLOCK', 'ESCALATE'];

/** Whole-percent share of part in whole, or null when nothing was counted: an empty count is never shown as 0%. */
export function percent(part: number, whole: number): number | null {
  return whole > 0 ? Math.round((part / whole) * 100) : null;
}

export interface MixSegment {
  readonly action: EngineAction;
  readonly count: number;
  /** Share of the resolved decisions, 0 to 100 with one decimal, for the bar width. */
  readonly share: number;
}

/** Segments of the decision mix bar; an action with no decision stays in the legend and takes no width. */
export function decisionMix(actions: StatsView['engineActions']): {
  readonly total: number;
  readonly segments: readonly MixSegment[];
} {
  const total = ENGINE_ACTIONS.reduce((sum, action) => sum + actions[action], 0);
  return {
    total,
    segments: ENGINE_ACTIONS.map((action) => ({
      action,
      count: actions[action],
      share: total > 0 ? Math.round((actions[action] / total) * 1000) / 10 : 0,
    })),
  };
}

/** Milliseconds as seconds with one decimal ("2.3"), or null when there was no decision to time. */
export function seconds(ms: number | null): string | null {
  return ms === null ? null : (ms / 1000).toFixed(1);
}

/** An instant as "2026-10-05 07:30 UTC": the statistics are counted in UTC, so the time says so. */
export function utcMinute(iso: string): string {
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}
