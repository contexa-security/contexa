import type { BenchmarkView } from '../../api/benchmark';

/**
 * How many times each case was sent, as the server counted the runs (벤치마크 계획 BM-S9: a measurement stopped
 * before its plan sent its cases fewer times than its repeat); an older portal's planned repeat otherwise.
 */
export function sentPerCase(view: BenchmarkView): string {
  const { fewestRunsPerCase: fewest, mostRunsPerCase: most } = view.scope;
  if (fewest !== undefined && most !== undefined && most > 0) {
    return fewest === most ? String(most) : `${fewest}~${most}`;
  }
  return view.scope.protocols.map((protocol) => protocol.repeat).join(', ') || '-';
}
