import { useSearchParams } from 'react-router-dom';
import type { BenchmarkRate, BenchmarkView, ControlScore } from '../../api/benchmark';
import { formatNumber } from '../format';

// The old benchmark's helpers read the portal's fields the shared types leave out; the scenario validation reuses them
// as they are and they move here at I-10 (DEC-50).
export { sentPerCase } from '../../pages/benchmark/benchScope';
export {
  judgmentOthers,
  mostLikelyActions,
  riskKinds,
  sharedNormals,
  type JudgmentRun,
  type JudgmentStep,
} from '../../pages/benchmark/benchShapes';

/** The five controls in the one order every table of the validation keeps. */
export const CONTROLS = ['A', 'B', 'C1', 'C2', 'D'] as const;
export type ControlKey = (typeof CONTROLS)[number];

const SETTING = /^[0-9a-f]{64}$/;

/** The measurement setting the validation shows (`?setting=`, 64 hex characters), the latest when none is named (ST-56). */
export function useValidationSetting(): string | null {
  const [params] = useSearchParams();
  const asked = params.get('setting');
  return asked && SETTING.test(asked) ? asked : null;
}

/** The case group the controls tab counts (`?suite=`): every case, or a group the server names. */
export function suiteOf(view: BenchmarkView, asked: string | null) {
  const suite = view.suites.find((candidate) => candidate.suite === asked) ?? null;
  return {
    suite,
    controls: suite ? suite.controls : view.controls,
    conclusions: suite ? suite.conclusions : view.conclusions,
  };
}

export function scoreOf(controls: readonly ControlScore[], control: string): ControlScore | null {
  return controls.find((score) => score.control === control) ?? null;
}

/** A share the server worked out, with one decimal (0.8182 → 81.8%). */
export function ratePercent(value: number | null, language: string): string {
  return value === null ? '—' : `${formatNumber(value * 100, language, 1)}%`;
}

/** A rate as "hits / total". */
export function rateCounts(rate: BenchmarkRate, language: string): string {
  return `${formatNumber(rate.hits, language)} / ${formatNumber(rate.total, language)}`;
}

/** A rate's 95% range ("61.5–92.7%"), when the server sent one. */
export function rateRange(rate: BenchmarkRate, language: string): string | null {
  return rate.low === null || rate.high === null
    ? null
    : `${formatNumber(rate.low * 100, language, 1)}–${formatNumber(rate.high * 100, language, 1)}%`;
}

/** The lowest number of attacks an existing control missed: what the summary sets Contexa's misses against. */
export function fewestExistingMisses(controls: readonly ControlScore[]): number | null {
  const misses = controls.filter((score) => score.control !== 'D').map((score) => score.missed);
  return misses.length > 0 ? Math.min(...misses) : null;
}
