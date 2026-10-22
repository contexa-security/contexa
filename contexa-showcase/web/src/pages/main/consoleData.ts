import type { useTranslation } from 'react-i18next';
import type { BeforeSendView, DecisionAnatomyView } from '../../api/anatomy';
import type { AnalysisStage, LiveDecision, LiveLayer } from '../../api/types';
import { comparisonRows } from '../../components/inside/Comparison';
import { count, seconds } from '../../journey/format';
import { membership, plainValue } from '../try/experience';
import { learnedCompared } from './evidence';

type T = ReturnType<typeof useTranslation>['t'];

/**
 * Whether the console can state what Contexa handed over: once its judgment arrived, or once an asynchronous response
 * went out (or was cut) before it; until then the request is held.
 */
export function contexaGaveKnown(layer: LiveLayer | null, decided: boolean): boolean {
  return layer !== null && (decided || layer.outcome === 'DELIVERED' || layer.outcome === 'CUT');
}

/**
 * The console's risk score in words (L-30): the engine's score once it came, "deciding" while Contexa decides, and a
 * dash for a run that ended without one.
 */
export function riskText(t: T, score: number | null | undefined, done: boolean): string {
  if (score !== null && score !== undefined) {
    return score.toFixed(2);
  }
  return done ? '—' : t('main.lane.deciding');
}

/**
 * The request a run sent again after its extra check, on the step that was checked: the stored check of that step, or
 * while the run is live the live check, on the request whose Contexa answer was the check (HTTP 401), not the latest.
 */
export function resentOf(
  check: {
    readonly answered?: boolean | null;
    readonly reissue_status?: number | null;
    readonly reissue_delivered?: number | null;
  } | null,
  live: {
    readonly stage: string;
    readonly reissueStatus: number | null;
    readonly reissueDeliveredItems?: number | null;
  } | null,
  stored: boolean,
  contexaStatus: number | null | undefined,
): { readonly items: number; readonly status: number } | null {
  if (check?.answered && typeof check.reissue_status === 'number') {
    return { items: check.reissue_delivered ?? 0, status: check.reissue_status };
  }
  if (!stored && contexaStatus === 401 && live?.stage === 'DONE' && live.reissueStatus !== null) {
    return { items: live.reissueDeliveredItems ?? 0, status: live.reissueStatus };
  }
  return null;
}

/**
 * The measured line of the console: the measurement's runs of the case and Contexa's judgments in them (a case of
 * several requests has a judgment per request), "all" only for more than one judgment.
 */
export function repeatLabel(actions: Readonly<Record<string, number>>): {
  readonly key: string;
  readonly action: string | null;
  readonly n: number;
} {
  const entries = Object.entries(actions).filter(([, n]) => n > 0);
  const n = entries.reduce((sum, [, k]) => sum + k, 0);
  const [single] = entries;
  if (entries.length === 1 && single) {
    return { key: n === 1 ? 'main.console.repeat.one' : 'main.console.repeat.all', action: single[0], n };
  }
  return { key: 'main.console.repeat.mixed', action: null, n };
}

/**
 * What the live console reads from the engine's records (설계서 2-2): the facts the engine compared and the lines of its
 * event log. They only name and lay out the record's values; they count nothing.
 */

/** One fact the engine compared, as the console lists it: the item, this time, the usual and the mark. */
export interface FactRow {
  readonly id: string;
  readonly name: string;
  readonly now: string;
  readonly against: string;
  /** different, the same as usual, an approval that covers it, a high sensitivity, or no record (never a difference). */
  readonly mark: 'different' | 'same' | 'matches' | 'high' | 'missing';
}

/** The items the console's fact check lists: the departures but the sensitivity, the approval and the sensitivity. */
const DEPARTURES_SHOWN = 3;

/** The engine's dimensions of the device: the browser and the system make one device item (N-DEP-1). */
const DEVICE_DIMENSIONS = ['operatingSystem', 'browser', 'device'];

/** The company facts named beside a missing approval: what else the business database checked. */
const AROUND_APPROVAL = new Set(['NO_TICKET', 'NOT_ON_CALL', 'NOT_ASSIGNED']);

/**
 * The device when the engine read it as the usual one (V-61, review 2026-10-21): the fact that sets the stolen account
 * apart from the real user is shown on both sides, as a difference or as the same. Null when the device differs (it is
 * among the differences then) or the engine did not compare it.
 */
function sameDevice(t: T, comparison: BeforeSendView): FactRow | null {
  const rows = comparison.usualVsNow.filter((row) => DEVICE_DIMENSIONS.includes(row.dimension));
  if (rows.length === 0 || rows.some((row) => membership(row.inUsual) !== 'same')) {
    return null;
  }
  return {
    id: 'device',
    name: t('dim.device'),
    now:
      rows
        .map((row) => (row.now === null ? '' : plainValue(t, row.dimension, row.now)))
        .filter((text) => text.length > 0)
        .join(' · ') || '-',
    against: t('main.facts.same'),
    mark: 'same',
  };
}

/**
 * The facts the engine compared in this request (설계서 2-2 사실 대조): up to three items that differ from the usual
 * behaviour pattern, the device when it is the usual one, the approval record from the company records, and the
 * resource's sensitivity, read from the engine's own input (the run's received view, or the latest run of the same
 * situation before it is stored). A missing approval is a missing record, not a difference (V-10).
 */
export function factRows(t: T, comparison: BeforeSendView): readonly FactRow[] {
  const { different } = comparisonRows(t, comparison);
  const departures = different
    .filter((row) => row.dimension !== 'resourceFamily')
    .slice(0, DEPARTURES_SHOWN)
    .map((row): FactRow => ({
      id: row.dimension,
      name: t(`dim.${row.dimension}`),
      now: row.now || '-',
      against: t('main.facts.usual', { usual: row.usual || t('dim.unknown') }),
      mark: 'different',
    }));
  const approval = comparison.businessFacts.find(
    (fact) => fact.code === 'APPROVAL_COVERS' || fact.code === 'NO_APPROVAL',
  );
  const approvalRow: readonly FactRow[] = approval
    ? [
        {
          id: 'approval',
          name: t('main.facts.approval'),
          now: t(`fact.${approval.code}`, { value: approval.value ?? '' }),
          against:
            approval.code === 'APPROVAL_COVERS'
              ? t('main.facts.approvalCovers', {
                  purpose: t(`main.purpose.${approval.value ?? 'OTHER'}`, {
                    defaultValue: approval.value ?? '',
                  }),
                })
              : comparison.businessFacts
                  .filter((fact) => AROUND_APPROVAL.has(fact.code))
                  .map((fact) => t(`fact.${fact.code}`, { value: fact.value ?? '' }))
                  .join(' · '),
          mark: approval.code === 'APPROVAL_COVERS' ? 'matches' : 'missing',
        },
      ]
    : [];
  const sensitivity = comparison.sensitivity;
  const sensitivityRow: readonly FactRow[] =
    sensitivity === 'HIGH' || sensitivity === 'CRITICAL'
      ? [
          {
            id: 'sensitivity',
            name: t('main.facts.sensitivity'),
            now: t(`dim.sensitivity.${sensitivity}`),
            against: t('main.facts.sensitivityNote'),
            mark: 'high',
          },
        ]
      : [];
  const device = departures.some((row) => row.id === 'device') ? null : sameDevice(t, comparison);
  return [...departures, ...(device ? [device] : []), ...approvalRow, ...sensitivityRow];
}

/**
 * Whether the engine's analysis went on to a second pass: a second-pass event came, or the first pass handed the
 * request on (ESCALATE). Without one the log names the analysis plainly, not "the first" (P-41).
 */
export function hasSecondPass(stages: readonly AnalysisStage[]): boolean {
  return stages.some(
    (stage) =>
      stage.type.startsWith('LAYER2_') || (stage.type === 'LAYER1_COMPLETE' && stage.action === 'ESCALATE'),
  );
}

/** The engine's action in the visitor's words with its own word beside it (P-15). */
function actionWords(t: T, action: string | null, final: boolean): string {
  if (action === null) {
    return '—';
  }
  const key = action === 'ESCALATE' && final ? 'main.event.action.held' : `main.event.action.${action}`;
  return t(key, { defaultValue: action });
}

/** One line of the engine's event log, from the engine's own analysis events as they arrive. */
export function eventLine(
  t: T,
  stage: AnalysisStage,
  context: {
    readonly anatomy: DecisionAnatomyView | null;
    readonly contexa: LiveLayer | null;
    readonly decision: LiveDecision | null;
    readonly language: string;
    /** The analysis went on to a second pass ({@link hasSecondPass}); only then is the first named the first. */
    readonly secondPass: boolean;
  },
): { readonly text: string; readonly tone: 'plain' | 'ai' | 'allow' | 'stop' | 'bad' } | null {
  const { anatomy, contexa, decision, language, secondPass } = context;
  const risk = (value: number | null) => (value === null ? '—' : value.toFixed(2));
  switch (stage.type) {
    case 'CONTEXT_COLLECTED': {
      const learned = anatomy ? learnedCompared(t, anatomy.figures, language) : null;
      return {
        text: learned ? t('main.event.context.counted', { learned }) : t('main.event.context'),
        tone: 'plain',
      };
    }
    case 'LAYER1_START': {
      const call = anatomy?.interpretation.calls[0] ?? null;
      return {
        text:
          call?.model && anatomy?.promptLines
            ? t(secondPass ? 'main.event.first.detail' : 'main.event.analysis.detail', {
                model: call.model,
                lines: count(anatomy.promptLines.total, language),
              })
            : t(secondPass ? 'main.event.first' : 'main.event.analysis'),
        tone: 'ai',
      };
    }
    // The engine does not say which layer a model call belonged to, so the second pass names no model: the call
    // lines show when each call answered.
    case 'LAYER2_START':
      return { text: t('main.event.second'), tone: 'ai' };
    case 'LAYER1_COMPLETE':
    case 'LAYER2_COMPLETE':
      return {
        text: t(
          stage.type === 'LAYER2_COMPLETE'
            ? 'main.event.secondDone'
            : secondPass
              ? 'main.event.firstDone'
              : 'main.event.analysisDone',
          {
            action: actionWords(t, stage.action, stage.type === 'LAYER2_COMPLETE'),
            risk: risk(stage.riskScore),
            confidence: risk(stage.confidence),
          },
        ),
        tone: stage.action === 'ALLOW' ? 'allow' : 'stop',
      };
    case 'DECISION_APPLIED':
      return {
        text: t('main.event.applied', {
          when: t(`main.applied.${decision?.applied ?? 'BEFORE_RESPONSE'}`),
          status: contexa?.httpStatus ?? '—',
          items: contexa ? count(contexa.deliveredItems, language) : '—',
        }),
        tone: stage.action === 'ALLOW' ? 'allow' : 'stop',
      };
    case 'ANALYSIS_ERROR':
      return { text: t('main.event.error'), tone: 'bad' };
    default:
      return null;
  }
}

/**
 * The model calls' answers as log lines, once the run's record holds them: each call's number, how long it took and its
 * tokens, placed after the engine event the record lists before it (`after` counts the events before the call). The
 * record does not share the log's clock, so a call line states its own duration instead of a time.
 */
export function callLines(
  t: T,
  anatomy: DecisionAnatomyView | null,
  language: string,
): readonly { readonly key: string; readonly after: number; readonly text: string }[] {
  if (!anatomy) {
    return [];
  }
  const { timeline, calls } = anatomy.interpretation;
  let events = 0;
  const lines: { key: string; after: number; text: string }[] = [];
  for (const entry of timeline) {
    if (entry.kind === 'EVENT') {
      events += 1;
      continue;
    }
    const call = calls.find((candidate) => candidate.callNo === entry.callNo) ?? null;
    if (entry.kind !== 'CALL_ANSWERED' || call === null) {
      continue;
    }
    lines.push({
      key: `call-${call.callNo}`,
      after: events,
      text: t('main.event.call', {
        n: call.callNo,
        seconds: call.elapsedMs === null ? '—' : seconds(call.elapsedMs),
        input: call.promptTokens === null ? '—' : count(call.promptTokens, language),
        output: call.completionTokens === null ? '—' : count(call.completionTokens, language),
      }),
    });
  }
  return lines;
}

/** The time of a log line as the log writes it ("+5.71초"), in the screen's own unit (P-14). */
export function atSeconds(t: T, atMs: number | null): string {
  return atMs === null ? '+ ·' : t('main.event.at', { seconds: (atMs / 1000).toFixed(2) });
}
