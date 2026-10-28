import { useSearchParams } from 'react-router-dom';
import type { BenchmarkRate, BenchmarkView } from '../../api/benchmark';

const SETTING = /^[0-9a-f]{64}$/;

/** The measurement setting the benchmark views show (?setting=), the latest when none is named (R-13). */
export function useBenchSetting() {
  const [params] = useSearchParams();
  const asked = params.get('setting');
  const setting = asked && SETTING.test(asked) ? asked : null;
  return { setting, search: setting ? `?setting=${setting}` : '' };
}

/** The case group the summary shows: every case, or a named group the rule controls were not written for. */
export function useBenchSuite(view: BenchmarkView | null) {
  const [params] = useSearchParams();
  const asked = params.get('suite');
  const suite = view?.suites.find((candidate) => candidate.suite === asked) ?? null;
  return {
    suite,
    controls: suite ? suite.controls : (view?.controls ?? []),
    conclusions: suite ? suite.conclusions : (view?.conclusions ?? null),
  };
}

/** A rate the server counted as "hits/total", the way every table and card of the benchmark writes it. */
export function fraction(rate: BenchmarkRate): string {
  return `${rate.hits}/${rate.total}`;
}

/** A share the server worked out, as a percent with one decimal (0.8182 → 81.8%). */
export function percent(value: number | null): string {
  return value === null ? '-' : `${Math.round(value * 1000) / 10}%`;
}

/**
 * A share always with one decimal (0.21 → 21.0%, 0 → 0.0%), for a rate and the ends of its range, so the numbers of
 * one range read alike (L-39 of docs/showcase/영상전-검토.md: never 0.8%~21% beside 0%~16.8%).
 */
export function percentFixed(value: number | null): string {
  return value === null ? '-' : `${(Math.round(value * 1000) / 10).toFixed(1)}%`;
}

/** The benchmark windows' names in the address (?modal=…). */
export const BENCH_MODALS = { method: 'method', approach: 'approach', benchCase: 'case' } as const;

/**
 * The benchmark's views (화면재편-구현계획 RO-3; B-2 of docs/showcase/벤치마크-구현계획.md adds the approaches), in the
 * one order the action bar walks them.
 */
export type BenchView = 'summary' | 'approaches' | 'cases' | 'judgment' | 'reasoning' | 'prompt' | 'limits' | 'agent';

// B-5 takes the old prompt view's place in the order; that view is no longer walked (its address leads to B-5).
export const BENCH_ORDER: readonly BenchView[] = [
  'summary',
  'approaches',
  'cases',
  'judgment',
  'reasoning',
  'limits',
];

export const BENCH_PATHS: Readonly<Record<BenchView, string>> = {
  summary: '/benchmark',
  approaches: '/benchmark/approaches',
  cases: '/benchmark/cases',
  judgment: '/benchmark/judgment',
  reasoning: '/benchmark/reasoning',
  prompt: '/benchmark/prompt',
  limits: '/benchmark/limits',
  // docs/agent Agent중심-화면 AS-11: beside the walk; the agent screens lead to it and its way back is the summary.
  agent: '/benchmark/agent',
};
