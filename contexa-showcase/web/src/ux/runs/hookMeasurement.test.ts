import { describe, expect, it } from 'vitest';
import type { BenchmarkView } from '../../api/benchmark';
import type { HookView } from '../../api/hook';
import benchmarkJson from '../test/fixtures/benchmark.test.json';
import hookJson from '../test/fixtures/hook.test.json';
import { hookRepeats } from './hookMeasurement';

const hook = hookJson as unknown as HookView;
const benchmark = benchmarkJson as unknown as BenchmarkView;

/** The fixture's benchmark with the S13 case replaced by five runs, the published one among them. */
function withS13(runResults: Readonly<Record<string, string>>): BenchmarkView {
  const runIds = Object.keys(runResults);
  const base = benchmark.cases.find((kase) => kase.key === 'S13') ?? benchmark.cases[0];
  if (!base) {
    throw new Error('the benchmark fixture has no case');
  }
  return {
    ...benchmark,
    cases: [
      ...benchmark.cases.filter((kase) => kase.key !== 'S13'),
      {
        ...base,
        key: 'S13',
        runs: runIds.length,
        runIds,
        runResults: Object.fromEntries(
          Object.entries(runResults).map(([runId, result]) => [runId, { D: result }]),
        ),
      },
    ],
  };
}

describe('how often the published recorded run came back (DEC-83)', () => {
  it('counts every run of the case in the measurement, not the run protocol alone', () => {
    const published = hook.attacker.runId;
    const view = withS13({
      [published]: 'STOPPED',
      'run-b': 'MISSED',
      'run-c': 'STOPPED',
      'run-d': 'MISSED',
      'run-e': 'STOPPED',
    });
    expect(hookRepeats(hook.attacker, view)).toEqual({ runs: 5, same: 3 });
  });

  it("keeps the portal's own count when the published run is not in the measurement", () => {
    const view = withS13({ 'run-b': 'STOPPED', 'run-c': 'STOPPED' });
    expect(hookRepeats(hook.attacker, view)).toEqual({
      runs: hook.attacker.measurement.runs,
      same: hook.attacker.measurement.sameResult,
    });
    expect(hookRepeats(hook.attacker, null)).toEqual({
      runs: hook.attacker.measurement.runs,
      same: hook.attacker.measurement.sameResult,
    });
  });
});
