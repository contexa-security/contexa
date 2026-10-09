import type { DecisionAnatomyView } from '../../api/anatomy';
import type { StepResult } from '../../api/types';
import type { Verdict } from '../../domain/verdict';
import type { MeterRow } from './CumulativeMeter';

/** The engine's decisions a meter row names. */
const VERDICTS = new Set(['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK']);

export function verdictOf(anatomy: DecisionAnatomyView | undefined): Verdict | null {
  const action = anatomy?.interpretation.recorded.finalAction ?? null;
  return action && VERDICTS.has(action) ? (action as Verdict) : null;
}

export function priorOf(result: StepResult | undefined): boolean {
  return result?.layers.find((layer) => layer.control === 'D')?.evidence.timing === 'PRIOR_DECISION';
}

/** One meter row per request from the stored anatomy and step result; every value is the record's. */
export function meterRows(
  anatomies: readonly (DecisionAnatomyView | undefined)[],
  results: readonly (StepResult | undefined)[],
): MeterRow[] {
  return anatomies.map((anatomy, index) => ({
    request: index + 1,
    observations: anatomy?.figures.workProfileObservations ?? null,
    deltas: anatomy?.figures.departureCount ?? null,
    verdict: verdictOf(anatomy),
    riskScore: anatomy?.interpretation.recorded.riskScore ?? null,
    prior: priorOf(results[index]),
  }));
}
