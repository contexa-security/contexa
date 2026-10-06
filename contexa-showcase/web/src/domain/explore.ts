import type { DeviceState, Slot, TicketState } from '../api/types';

/**
 * The facts the visitor changes in the hands-on experience (docs/showcase/체험우선-설계.md; the values of
 * docs/showcase/P4-설계.md 1절, approval Q-25). They name the combinations the portal runs.
 */
export const EMPLOYEES = ['adm-a', 'eng-k'] as const;
export const SLOTS: readonly Slot[] = ['DAWN', 'MORNING', 'AFTERNOON', 'EVENING'];
export const ITEMS = [40, 480, 4831, 6200] as const;
export const TICKETS: readonly TicketState[] = ['NONE', 'MISMATCH', 'MATCH'];
export const DEVICES: readonly DeviceState[] = ['USUAL', 'NEW'];

export interface Selection {
  readonly employee: string;
  readonly slot: Slot;
  readonly items: number;
  readonly ticket: TicketState;
  readonly device: DeviceState;
}

export function keyOf(selection: Selection): string {
  return [selection.employee, selection.slot, selection.items, selection.ticket, selection.device].join('.');
}
