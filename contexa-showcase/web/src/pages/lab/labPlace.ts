import type { TFunction } from 'i18next';
import type { BeforeSendView } from '../../api/anatomy';
import type { LabCase, LabConditions, LabOptions } from '../../api/lab';
import { count } from '../../journey/format';
import type { BarWords } from '../try/steps/LiveRunBar';

/**
 * The lab's place in the address (7.6, every step has its own address): the case and the conditions the visitor
 * changed, so a reload, the back button or a shared link returns to the same step with the same change. Only what the
 * visitor changed is in the address; choosing the original value again takes it out.
 */
export const CONDITION_KEYS = [
  'employee',
  'timeSlot',
  'place',
  'device',
  'operation',
  'target',
  'items',
  'approval',
  'ticket',
  'claim',
  'onCall',
] as const;
export type ConditionKey = (typeof CONDITION_KEYS)[number];

/** The conditions one step changes in the plain mode (lab-2): time, place, device, count and the approval record. */
export const ONE_CHANGE: readonly ConditionKey[] = ['timeSlot', 'place', 'device', 'items', 'approval'];

/**
 * The lab's screens in the order a visitor walks them (화면재편 R7, RO-2): the top bar names the step and shows how far
 * along the walk the screen is. The rule tightening is a screen of its own beside the walk, so it has no place in it.
 */
export const LAB_WALK = ['entrance', 'case', 'change', 'before', 'send', 'result'] as const;
export type LabStep = (typeof LAB_WALK)[number] | 'rules' | 'agent';

/** How far along the walk a step is (0-100), for the top bar's thin bar; none for the rule tightening. */
export function walkProgress(step: LabStep): number | null {
  const at = (LAB_WALK as readonly string[]).indexOf(step);
  return at < 0 ? null : Math.round(((at + 1) / LAB_WALK.length) * 100);
}

/**
 * The top bar's track (L-24): as far along the walk as the step is, and empty beside the walk (the rule tightening), so
 * the bar keeps one height on every lab screen and the body never jumps between them.
 */
export function barProgress(step: LabStep): number {
  return walkProgress(step) ?? 0;
}

/** The steps the entrance numbers: the walk after the entrance itself (V-30). */
export const WALK_STEPS = LAB_WALK.slice(1);

/** A step's number in the walk and how many steps it has (V-30); none for the entrance and the rule tightening. */
export function walkNumber(step: LabStep): { readonly n: number; readonly total: number } | null {
  const at = (WALK_STEPS as readonly string[]).indexOf(step);
  return at < 0 ? null : { n: at + 1, total: WALK_STEPS.length };
}

/**
 * The words of the lab's live bars (T-01, B-07): a refusal and a cut are named as the deck's result chips (blocked,
 * blocked after some left), and Contexa's line says its AI is still judging while a streamed export goes out.
 */
export const LAB_BAR_WORDS: BarWords = {
  denied: 'lab.r7.run.denied',
  deniedOnly: 'lab.r7.run.deniedOnly',
  cutAtOf: 'lab.r7.run.cutAtOf',
  cutAt: 'lab.r7.run.cutAt',
  judgingStream: 'lab.r7.run.judgingStream',
  judgingStreamNoTotal: 'lab.r7.run.judgingStreamNoTotal',
};

/** Whether a line the judgment rules always keep applies in the engine's input, as the engine found it. */
export type LineState = 'applies' | 'clear' | 'unknown' | 'none' | 'modelJudges';

export function lineState(view: BeforeSendView | null): LineState {
  if (!view) {
    return 'none';
  }
  // SC-2: a v21 input states no line the rules always keep; the model judges from the facts.
  if (view.modelJudges) {
    return 'modelJudges';
  }
  // N-K5-1: the minimum action rules the engine found met, or the boundary of a text without them.
  const applies = view.minimumRules
    ? view.minimumRules.applies
    : view.boundary
      ? view.boundary.applies
      : null;
  return applies === null ? 'unknown' : applies ? 'applies' : 'clear';
}

/** What the case's definition sets as the right handling: a request to stop, one to let through, or nothing. */
export type Expectation = 'stop' | 'pass' | 'none';

export function expectationOf(classification: string | null | undefined): Expectation {
  return classification === 'THREAT' ? 'stop' : classification === 'NORMAL' ? 'pass' : 'none';
}

/**
 * A situation's name in plain words (화면재편-기획안 11절): the lab's own name for the case key, else the title the
 * case definition carries (a case added later than these names).
 */
export function situationName(
  t: TFunction,
  key: string,
  title: Readonly<Record<string, string>> | null | undefined,
  language: string,
): string {
  return t(`lab.r7.case.name.${key}`, { defaultValue: title?.[language] ?? key });
}

const BOOLEAN_KEYS = new Set<ConditionKey>(['approval', 'onCall']);

/** The changed conditions the address carries. */
export function readChanges(params: URLSearchParams): Partial<LabConditions> {
  const changes: Record<string, unknown> = {};
  for (const key of CONDITION_KEYS) {
    const value = params.get(key);
    if (value === null) {
      continue;
    }
    changes[key] = BOOLEAN_KEYS.has(key) ? value === 'true' : key === 'items' ? Number(value) : value;
  }
  return changes as Partial<LabConditions>;
}

/** The address query of a case with its changed conditions. */
export function labQuery(caseKey: string, changes: Partial<LabConditions>): string {
  const params = new URLSearchParams({ case: caseKey });
  for (const key of CONDITION_KEYS) {
    const value = changes[key];
    if (value !== undefined && value !== null) {
      params.set(key, String(value));
    }
  }
  return params.toString();
}

/** The changed conditions with one condition set, or taken out when it is the original value again. */
export function withChange(
  changes: Partial<LabConditions>,
  key: ConditionKey,
  value: string | number | boolean,
  original: unknown,
): Partial<LabConditions> {
  const others = Object.fromEntries(Object.entries(changes).filter(([name]) => name !== key));
  return (value === original ? others : { ...others, [key]: value }) as Partial<LabConditions>;
}

/** The values a condition can take, as the lab offers them (the business database's items and time slots). */
export function choicesOf(key: ConditionKey, options: LabOptions): readonly (string | number | boolean)[] {
  switch (key) {
    case 'employee':
      return options.employees.map((employee) => employee.key);
    case 'timeSlot':
      return options.timeSlots.map((slot) => slot.slot);
    case 'place':
      return ['OFFICE', 'TRAVEL', 'EXTERNAL'];
    case 'device':
      return ['USUAL', 'NEW'];
    case 'operation':
      return options.operations;
    case 'target':
      return ['ASSIGNED', 'UNASSIGNED'];
    case 'items':
      return options.items;
    case 'approval':
    case 'onCall':
      return [false, true];
    case 'ticket':
      return ['NONE', 'COVERS', 'OTHER_PROJECT'];
    case 'claim':
      return ['NONE', 'REAL', 'FAKE'];
    default:
      return [];
  }
}

/** The conditions a case of several requests keeps as designed (the portal refuses them: STEPS_FIXED). */
const STEPS_FIXED = new Set<ConditionKey>(['operation', 'target', 'items', 'claim']);

/** Whether the visitor can change a condition of the case: the case states it, and its requests allow it. */
export function changeable(key: ConditionKey, labCase: LabCase): boolean {
  const value = labCase.conditions[key];
  return value !== null && value !== undefined && !(labCase.requests.length > 1 && STEPS_FIXED.has(key));
}

/** A condition's value in the visitor's words. */
export function conditionText(
  t: TFunction,
  key: ConditionKey,
  value: unknown,
  options: LabOptions,
  language: string,
): string {
  if (value === null || value === undefined) {
    return t('lab.value.none');
  }
  if (key === 'employee') {
    return options.employees.find((employee) => employee.key === value)?.displayName ?? String(value);
  }
  if (key === 'timeSlot') {
    const slot = options.timeSlots.find((candidate) => candidate.slot === value);
    return t(`lab.slot.${String(value)}`, { time: slot?.representativeTime ?? '' });
  }
  if (typeof value === 'boolean') {
    return t(value ? 'lab.value.yes' : 'lab.value.no');
  }
  if (key === 'items') {
    return t('lab.value.items', { n: count(Number(value), language) });
  }
  return t(`lab.${key}.${String(value)}`);
}
