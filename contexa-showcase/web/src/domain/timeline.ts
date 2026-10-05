import type { TFunction } from 'i18next';
import type { Evidence, TimelineEvent } from '../api/types';
import type { TimelineEntry } from '../components/AnalysisTimeline';

/**
 * Timeline lines of one engine step (P3-BE-03). The times are the server's stored values unchanged; only the event
 * names are localized, from the engine's event type codes.
 */
export const KNOWN_EVENTS = new Set([
  'CONTEXT_COLLECTED',
  'LAYER1_START',
  'LAYER1_COMPLETE',
  'LAYER2_START',
  'LAYER2_COMPLETE',
  'DECISION_APPLIED',
  'ANALYSIS_ERROR',
]);

const NUMBER = new Intl.NumberFormat('en-US');

export function timelineEntries(evidence: Evidence, t: TFunction): TimelineEntry[] {
  if (evidence.timeline.length === 0) {
    return [];
  }
  const entries: TimelineEntry[] = evidence.timeline.map((event, index) => ({
    key: `${event.type}-${index}`,
    kind: 'engine',
    label: KNOWN_EVENTS.has(event.type) ? t(`timeline.event.${event.type}`) : t('timeline.unknown', { code: event.type }),
    atMs: event.atMs,
    note: note(event, t),
  }));
  if (evidence.responseMs !== null) {
    entries.push({ key: 'response', kind: 'response', label: t('timeline.response'), atMs: evidence.responseMs, note: null });
  }
  return entries.sort((left, right) => left.atMs - right.atMs);
}

/** When the decision took effect relative to the response: before it (sync) or after it (applied from the next request). */
export function timelineSummary(evidence: Evidence, t: TFunction): string | null {
  const applied = evidence.timeline.find((event) => event.type === 'DECISION_APPLIED');
  if (!applied || evidence.responseMs === null) {
    return null;
  }
  const gap = applied.atMs - evidence.responseMs;
  return gap > 0
    ? t('timeline.appliedAfter', { ms: NUMBER.format(gap) })
    : t('timeline.appliedBefore', { ms: NUMBER.format(-gap) });
}

function note(event: TimelineEvent, t: TFunction): string | null {
  if (event.action && event.elapsedMs !== null) {
    return t('timeline.actionElapsed', { action: event.action, ms: NUMBER.format(event.elapsedMs) });
  }
  return event.action;
}
