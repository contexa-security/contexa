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

/** The benchmark windows' names in the address (?modal=…). */
export const BENCH_MODALS = { method: 'method', approach: 'approach', benchCase: 'case' } as const;
