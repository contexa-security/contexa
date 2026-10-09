import type { LabConditions } from '../api/lab';

/** The conditions of a case in the order the lab lists them. */
export const CONDITION_FIELDS: readonly (keyof LabConditions)[] = [
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
];

/** Conditions that live only in the company records, not in the request itself. */
const RECORD_FIELDS = new Set<keyof LabConditions>(['approval', 'ticket', 'claim', 'onCall']);

export interface ConditionComparison {
  readonly same: readonly (keyof LabConditions)[];
  readonly different: readonly (keyof LabConditions)[];
  /** Every difference is in the company records: the two requests themselves carry the same conditions. */
  readonly recordsOnly: boolean;
}

/**
 * Which conditions two cases share and which they do not, from the case definitions as the portal answers them
 * (H-09 #28). A condition a case leaves open (a multi-request case whose requests differ) is in neither list, so
 * nothing is claimed about it.
 */
export function compareConditions(first: LabConditions, second: LabConditions): ConditionComparison {
  const same: (keyof LabConditions)[] = [];
  const different: (keyof LabConditions)[] = [];
  for (const field of CONDITION_FIELDS) {
    const left = first[field];
    const right = second[field];
    if (left === null || right === null) {
      continue;
    }
    (left === right ? same : different).push(field);
  }
  return {
    same,
    different,
    recordsOnly: different.length > 0 && different.every((field) => RECORD_FIELDS.has(field)),
  };
}
