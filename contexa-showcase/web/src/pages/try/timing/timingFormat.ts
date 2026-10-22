import type { MeasuredCase, MeasuredRange, MeasuredRun } from '../../../api/measured';
import { count, seconds } from '../../../journey/format';

/**
 * Formatting of the timing part's measured values (화면재편 4-0 to 4-3): the server's ranges as one value when both
 * ends are the same, else "min~max". Nothing is computed; numbers are only formatted.
 */
export function secondsRange(range: MeasuredRange): string {
  return range.min === range.max ? seconds(range.min) : `${seconds(range.min)}~${seconds(range.max)}`;
}

export function itemsRange(range: MeasuredRange, language: string): string {
  return range.min === range.max
    ? count(range.min, language)
    : `${count(range.min, language)}~${count(range.max, language)}`;
}

/** The measured run a screen shows as the example of a case: the one the server marks as the middle by analysis time. */
export function middleRun(measured: MeasuredCase | null | undefined): MeasuredRun | null {
  return measured?.list.find((run) => run.runId === measured.middleRun) ?? null;
}

/** The single result every run of a measured case had, as the server counted it; null when the runs differ. */
export function onlyResult(measured: MeasuredCase): string | null {
  const results = Object.keys(measured.results);
  return measured.allSame && results.length === 1 ? (results[0] ?? null) : null;
}
