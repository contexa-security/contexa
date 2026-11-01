import type { TFunction } from 'i18next';
import type { BeforeSendView } from '../../api/anatomy';
import type { LabCase, LabOptions } from '../../api/lab';
import { formatNumber } from '../format';

/**
 * The conditions of a case the policy simulator lets the visitor change, their values and their words, and whether a
 * line the judgment rules always keep applies (moved from the old screens' pages/lab/labPlace.ts at I-10, DEC-80).
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
    return t('ux.cond.value.none');
  }
  if (key === 'employee') {
    return options.employees.find((employee) => employee.key === value)?.displayName ?? String(value);
  }
  if (key === 'timeSlot') {
    const slot = options.timeSlots.find((candidate) => candidate.slot === value);
    return t(`ux.cond.slot.${String(value)}`, { time: slot?.representativeTime ?? '' });
  }
  if (typeof value === 'boolean') {
    return t(value ? 'ux.cond.value.yes' : 'ux.cond.value.no');
  }
  if (key === 'items') {
    return t('ux.cond.value.items', { n: formatNumber(Number(value), language) });
  }
  return t(`ux.cond.${key}.${String(value)}`);
}
