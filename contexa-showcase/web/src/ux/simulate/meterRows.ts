import type { DecisionAnatomyView } from '../../api/anatomy';
import type { StepResult } from '../../api/types';
import type { Verdict } from '../../domain/verdict';

/**
 * A request's decision and whether a decision already in force refused it, read from its stored records (moved from
 * the old screens' components/inside/meterRows.ts at I-10, DEC-80).
 */

/** The engine's decisions a request's row names. */
const VERDICTS = new Set(['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK']);

export function verdictOf(anatomy: DecisionAnatomyView | undefined): Verdict | null {
  const action = anatomy?.interpretation.recorded.finalAction ?? null;
  return action && VERDICTS.has(action) ? (action as Verdict) : null;
}

/** Refused because a decision already in force applied (decision source PRIOR_DECISION). */
export function priorOf(result: StepResult | undefined): boolean {
  return result?.layers.find((layer) => layer.control === 'D')?.evidence.timing === 'PRIOR_DECISION';
}
