import type { AnalysisStage } from '../../api/types';

/** The nine steps one request goes through inside Contexa (panel slide), in order. */
export const INSIDE_CELLS = [
  'request',
  'usual',
  'company',
  'history',
  'prompt',
  'judgement',
  'decision',
  'followUp',
  'learning',
] as const;
export type InsideCellId = (typeof INSIDE_CELLS)[number];

/** Waiting to start, in progress (clock), done (check), or the decision (highlighted). */
export type InsideCellState = 'waiting' | 'active' | 'done' | 'decision';

/** The cells the engine's own analysis events tell; follow-up and learning come from the run's record. */
export type AnalysedCellId = Exclude<InsideCellId, 'followUp' | 'learning'>;

/**
 * Which of the first seven cells the engine's analysis of one request has reached, read only from the events it
 * announced (panel slide, C-12): the context it collected covers the usual behaviour, the company records and the past
 * records; the first layer starting means the prompt went out; the applied decision closes the judgement, and the
 * decision cell lights once the decision block itself arrived. Null stages mean the request is not with the engine yet.
 */
export function analysedCells(
  stages: readonly AnalysisStage[] | null,
  decisionArrived: boolean,
): Readonly<Record<AnalysedCellId, InsideCellState>> {
  const seen = new Set((stages ?? []).map((stage) => stage.type));
  const collected = seen.has('CONTEXT_COLLECTED');
  const prompted = seen.has('LAYER1_START');
  const closed = seen.has('DECISION_APPLIED') || seen.has('ANALYSIS_ERROR');
  const context: InsideCellState = collected ? 'done' : stages === null ? 'waiting' : 'active';
  return {
    request: stages === null ? 'active' : 'done',
    usual: context,
    company: context,
    history: context,
    prompt: prompted ? 'done' : collected ? 'active' : 'waiting',
    judgement: closed ? 'done' : prompted ? 'active' : 'waiting',
    decision: decisionArrived ? 'decision' : closed ? 'active' : 'waiting',
  };
}
