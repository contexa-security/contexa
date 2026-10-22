import { describe, expect, it } from 'vitest';
import { benchmark } from './benchFixture';
import { sentPerCase } from './benchScope';

// 벤치마크 계획 BM-S9: a measurement stopped before its plan says how many times each case was sent, as measured.
describe('how many times each case was sent', () => {
  it("takes the server's counts of the runs per case", () => {
    const view = benchmark();
    expect(sentPerCase({ ...view, scope: { ...view.scope, fewestRunsPerCase: 1, mostRunsPerCase: 2 } })).toBe(
      '1~2',
    );
    expect(sentPerCase({ ...view, scope: { ...view.scope, fewestRunsPerCase: 5, mostRunsPerCase: 5 } })).toBe(
      '5',
    );
  });

  it("falls back to the protocols' planned repeat from a portal that sends no counts", () => {
    expect(sentPerCase(benchmark())).toBe('5');
  });
});
