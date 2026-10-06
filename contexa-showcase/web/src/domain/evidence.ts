import type { TFunction } from 'i18next';
import type { EngineReason, Layer } from '../api/types';
import type { EvidenceChain } from '../components/EvidenceDrawer';
import { engineReasonLine, ruleReason, timingLine } from './reasons';
import { timelineEntries, timelineSummary } from './timeline';
import { OUTCOME_KEYS } from './verdict';

/** The evidence chain of one control's result (deck p.11): the four linked records and, for the engine, its timeline. */
export function evidenceChain(layer: Layer, t: TFunction): EvidenceChain {
  const chain: EvidenceChain = {
    decisionId: layer.evidence.decisionId,
    verdict: layer.evidence.verdict,
    unresolved: layer.evidence.unresolved,
    timing: timingLine(layer.evidence.timing, t),
    httpStatus: layer.evidence.httpStatus,
    outcome: t(OUTCOME_KEYS[layer.evidence.outcome]),
  };
  const entries = timelineEntries(layer.evidence, t);
  const withStream = layer.evidence.stream ? { ...chain, stream: layer.evidence.stream } : chain;
  const withTimeline =
    entries.length > 0
      ? { ...withStream, timeline: { entries, summary: timelineSummary(layer.evidence, t) } }
      : withStream;
  return layer.evidence.engineReasoning
    ? { ...withTimeline, engineReasoning: layer.evidence.engineReasoning }
    : withTimeline;
}

/** The one-line reason of a control's result: the engine's structured factors for Contexa, the rule for the others. */
export function reasonLine(layer: Layer, engineReason: EngineReason | null, t: TFunction): string {
  return layer.control === 'D' ? engineReasonLine(layer, engineReason, t) : ruleReason(layer, t);
}
