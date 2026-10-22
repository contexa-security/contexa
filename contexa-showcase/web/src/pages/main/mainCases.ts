import type { TFunction } from 'i18next';
import type { RecapLine } from '../../api/journey';
import type { LabCase, LabEmployee, LabOptions, LabRequest } from '../../api/lab';
import type { LiveDecision, LiveLayer } from '../../api/types';
import { count } from '../../journey/format';

/**
 * The cases the main flow sends (최종화면-구현계획 2절, IN-6 확정 설계): the stolen account of group 2, the owner's
 * same export of group 4 and the insider of group 5, the cases whose measured runs every existing control let through
 * (G1 of docs/showcase/프롬프트-v21-구현계획.md). The insider's pair, the same person's normal work in the same way, is
 * shown measured on the insider's last screen.
 */
export type Role = 'attacker' | 'owner' | 'insider';

export const MAIN_CASES: Readonly<Record<Role, string>> = { attacker: 'S13', owner: 'S13T', insider: 'S16' };

/** The insider's normal pair: the same person, time, device and way, with design documents. */
export const INSIDER_NORMAL = 'S16T';

/** The main flow's addresses of each role's screens. */
export const ROLE_PATHS: Readonly<Record<Role, { readonly request: string; readonly console: string }>> = {
  attacker: { request: '/attack/request', console: '/attack/console' },
  owner: { request: '/normal/request', console: '/normal/console' },
  insider: { request: '/insider/request', console: '/insider/console' },
};

/** The screen numbers of each role's request and console. */
export const ROLE_NUMBERS: Readonly<Record<Role, { readonly request: string; readonly console: string }>> = {
  attacker: { request: '2-1', console: '2-2' },
  owner: { request: '4-1', console: '4-2' },
  insider: { request: '5-1', console: '5-2' },
};

/** The experience each role's call before sending is stored under (JourneyViews.EXPERIENCE_CASES). */
export const ROLE_EXPERIENCES: Readonly<Record<Role, 'E1' | 'E2' | 'E3'>> = {
  attacker: 'E1',
  owner: 'E2',
  insider: 'E3',
};

/** The case and its employee from the case list; null until both are known. */
export function caseOf(
  options: LabOptions | undefined,
  key: string,
): { readonly labCase: LabCase; readonly employee: LabEmployee } | null {
  const labCase = options?.cases.find((candidate) => candidate.key === key) ?? null;
  const employee =
    options?.employees.find((candidate) => candidate.key === labCase?.conditions.employee) ?? null;
  return labCase && employee ? { labCase, employee } : null;
}

/**
 * Whether a request opens another document of a project an earlier request of the case opened (another position), so
 * its name says so instead of repeating the first one's (4-4's second drawing, L-36).
 */
export function readsAgain(requests: readonly LabRequest[], index: number): boolean {
  const request = requests[index];
  const document = request?.operation === 'DOCUMENT_READ' ? request.document : null;
  if (!document) {
    return false;
  }
  return requests
    .slice(0, index)
    .some(
      (earlier) =>
        earlier.operation === 'DOCUMENT_READ' &&
        earlier.document !== null &&
        earlier.document.project === document.project &&
        earlier.document.fact === document.fact &&
        earlier.document.position !== document.position,
    );
}

/** The person's name in the visitor's words (관리자 A), keyed by the employee the case names. */
export function personName(t: TFunction, employee: LabEmployee): string {
  return t(`person.${employee.key}`, { defaultValue: employee.displayName });
}

/** A company time as the screens write it: the weekday and the clock time ("수요일 03:17"), read from the record. */
export function companyClock(t: TFunction, iso: string | null | undefined): string | null {
  if (!iso) {
    return null;
  }
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) {
    return null;
  }
  // The record's company time is written in UTC (the demo company's clock); its weekday is Monday = 1.
  const weekday = ((at.getUTCDay() + 6) % 7) + 1;
  const clock = `${String(at.getUTCHours()).padStart(2, '0')}:${String(at.getUTCMinutes()).padStart(2, '0')}`;
  return t('main.clock', { day: t(`main.weekday.${weekday}`), clock });
}

/** The chip kinds of the console (v4): each with its own color, always with its word and an icon. */
export type ChipKind = 'allow' | 'auth' | 'block' | 'bad' | 'ok' | 'wait';

/** Contexa's judgment as the console names it: the word and the chip kind. */
export function verdictChip(decision: Pick<LiveDecision, 'finalAction' | 'unresolved'>): {
  readonly key: string;
  readonly kind: ChipKind;
} {
  if (decision.unresolved) {
    return { key: 'main.verdict.failed', kind: 'bad' };
  }
  switch (decision.finalAction) {
    case 'ALLOW':
      return { key: 'main.verdict.ALLOW', kind: 'allow' };
    case 'CHALLENGE':
      return { key: 'main.verdict.CHALLENGE', kind: 'auth' };
    case 'ESCALATE':
      return { key: 'main.verdict.ESCALATE', kind: 'block' };
    case 'BLOCK':
      return { key: 'main.verdict.BLOCK', kind: 'block' };
    default:
      return { key: 'main.verdict.failed', kind: 'bad' };
  }
}

/**
 * The rules control D records when a decision already in force refused the request; such a request gets no decision
 * of its own (RunOrchestrator.engineDecision), so its refusal is its result.
 */
export const PRIOR_REFUSALS: ReadonlySet<string> = new Set(['ACCOUNT_BLOCKED', 'MFA_CHALLENGE_REQUIRED']);

/** The judgments that keep the data in until someone acts: a stop, an extra check or a hold for review. */
export const KEEPS_IN = new Set(['BLOCK', 'ESCALATE', 'CHALLENGE']);

/** A scored result in the console's words: the server's reading of the run against the case's ground truth. */
/** The business results a run is scored with; anything else (not scored, unresolved, none) has no result to show. */
const SCORED: ReadonlySet<string> = new Set([
  'STOPPED',
  'PARTLY_STOPPED',
  'MISSED',
  'PASSED',
  'PASSED_AFTER_CHECK',
  'HALTED',
]);

export function isScored(result: string | undefined): boolean {
  return result !== undefined && SCORED.has(result);
}

/** The prompt lines each condition of 6-2 speaks to: the changed value and the engine's comparison with the usual. */
const CHANGE_LINES: Readonly<Record<'time' | 'size' | 'device', readonly string[]>> = {
  time: ['Time', 'DeviationsFromBaseline', 'SameAsBaseline'],
  size: ['Size', 'DeviationsFromBaseline', 'SameAsBaseline'],
  device: ['Device', 'DeviationsFromBaseline', 'SameAsBaseline'],
};

/** The changed prompt lines of 6-2 split into those the changed condition speaks to and the others, each in order. */
export function splitChanged<L extends { readonly label: string }>(
  changed: readonly L[],
  change: 'time' | 'size' | 'device',
): { readonly related: readonly L[]; readonly other: readonly L[] } {
  const related = CHANGE_LINES[change];
  return {
    related: changed.filter((line) => related.includes(line.label)),
    other: changed.filter((line) => !related.includes(line.label)),
  };
}

export function resultChip(result: string | undefined): { readonly key: string; readonly kind: ChipKind } {
  switch (result) {
    case 'STOPPED':
      return { key: 'main.result.STOPPED', kind: 'block' };
    case 'PARTLY_STOPPED':
      return { key: 'main.result.PARTLY_STOPPED', kind: 'auth' };
    case 'MISSED':
      return { key: 'main.result.MISSED', kind: 'bad' };
    case 'PASSED':
      return { key: 'main.result.PASSED', kind: 'allow' };
    case 'PASSED_AFTER_CHECK':
      return { key: 'main.result.PASSED_AFTER_CHECK', kind: 'auth' };
    case 'HALTED':
      return { key: 'main.result.HALTED', kind: 'bad' };
    default:
      return { key: 'main.result.none', kind: 'wait' };
  }
}

/**
 * How a lane of an existing approach ended for the case, in the console's words (설계서 용어: 미탐 · 오탐). A run with no
 * ground truth (`threat` null: a condition changed on 6-2) is named by what the approach did, the same words for every
 * approach, never as missed or a false alarm.
 */
export function laneChip(
  layer: LiveLayer,
  threat: boolean | null,
): { readonly key: string; readonly kind: ChipKind } {
  const leaked = layer.deliveredItems > 0;
  if (layer.outcome === 'CUT') {
    return threat === false
      ? { key: 'main.lane.normal.cut', kind: 'bad' }
      : { key: 'main.lane.cut', kind: 'auth' };
  }
  if (leaked || layer.outcome === 'DELIVERED') {
    return threat ? { key: 'main.lane.through', kind: 'bad' } : { key: 'main.lane.allowed', kind: 'allow' };
  }
  if (layer.outcome === 'UNRESOLVED') {
    return { key: 'main.lane.unresolved', kind: 'bad' };
  }
  return threat === false
    ? { key: 'main.lane.halted', kind: 'bad' }
    : { key: 'main.lane.stopped', kind: 'block' };
}

/**
 * Contexa's cell of a result table (V-06): its own decision with the items that left, so a stop by an extra check reads
 * as the extra check it was, not as a result word that reads "blocked". Null without a decision (the table then shows
 * the scored result).
 */
export function contexaCell(
  action: string | null | undefined,
  items: number,
): { readonly key: string; readonly kind: ChipKind; readonly items: number } | null {
  if (!action) {
    return null;
  }
  return { ...verdictChip({ finalAction: action, unresolved: false }), items };
}

/**
 * A visitor's run in a result table, in words: an existing approach's scored result, and Contexa's own decision with the
 * items that left (V-06), the scored result only when Contexa made no decision.
 */
export function runCell(
  t: TFunction,
  language: string,
  run: Pick<RecapLine, 'engineAction' | 'exposedItems' | 'business'>,
  control: string,
): { readonly kind: ChipKind; readonly words: string } {
  const decision = control === 'D' ? contexaCell(run.engineAction, run.exposedItems) : null;
  if (!decision) {
    const chip = resultChip(run.business[control]);
    return { kind: chip.kind, words: t(chip.key) };
  }
  return {
    kind: decision.kind,
    words: t('main.lane.out', {
      word: t(decision.key),
      count: decision.items,
      items: count(decision.items, language),
    }),
  };
}

/** The requests of a run Contexa decided itself, in order; a request refused by a decision in force has none. */
export function decidedSteps(
  verdicts: readonly { readonly score: { readonly stepNo: number; readonly finalAction: string | null } }[],
): { readonly stepNo: number; readonly action: string }[] {
  return verdicts.flatMap((verdict) =>
    verdict.score.finalAction === null
      ? []
      : [{ stepNo: verdict.score.stepNo, action: verdict.score.finalAction }],
  );
}

/** The request a run's decisions are shown from first: the first decision that kept the data in, else the first one. */
export function firstStopping(
  decided: readonly { readonly stepNo: number; readonly action: string }[],
): number {
  return (decided.find((step) => KEEPS_IN.has(step.action)) ?? decided[0])?.stepNo ?? 1;
}

/**
 * The line the approval-record rule's footnote adds (V-12): the footnote keeps the deck's words (*사례 조건을 보고 써
 * 둔 규칙), and only when every case on the screen is of the group no rule was written for (RULE_BLIND, as the
 * measurement records its groups) it says that they are not in those conditions. Null otherwise.
 */
export function blindNote(blind: readonly string[], cases: readonly string[]): string | null {
  if (cases.length === 0 || !cases.every((key) => blind.includes(key))) {
    return null;
  }
  return cases.length > 1 ? 'main.4-3.blindNote' : 'main.4-3.blindOne';
}
