import type { TFunction } from 'i18next';
import type { LabCase, LabConditions, LabOptions } from '../../api/lab';
import { count } from '../../journey/format';

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
