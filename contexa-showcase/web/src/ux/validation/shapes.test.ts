import { describe, expect, it } from 'vitest';
import type { BenchmarkView } from '../../api/benchmark';
import benchmark from '../test/fixtures/benchmark.test.json';
import { sentPerCase } from './shapes';

const view = benchmark as unknown as BenchmarkView;

// 벤치마크 계획 BM-S9: a measurement stopped before its plan says how many times each case was sent, as measured.
describe('how many times each case was sent', () => {
  it("takes the server's counts of the runs per case", () => {
    expect(sentPerCase({ ...view, scope: { ...view.scope, fewestRunsPerCase: 1, mostRunsPerCase: 2 } })).toBe(
      '1~2',
    );
    expect(sentPerCase({ ...view, scope: { ...view.scope, fewestRunsPerCase: 5, mostRunsPerCase: 5 } })).toBe(
      '5',
    );
  });

  it("falls back to the protocols' planned repeat from a portal that sends no counts", () => {
    const older = Object.fromEntries(
      Object.entries(view.scope).filter(([name]) => !name.endsWith('RunsPerCase')),
    ) as unknown as BenchmarkView['scope'];
    expect(sentPerCase({ ...view, scope: older })).toBe('5');
  });
});
