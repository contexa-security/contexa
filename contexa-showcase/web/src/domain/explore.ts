import type { DeviceState, Slot, TicketState } from '../api/types';

/** The facts the visitor changes on screen 3 (deck p.13, docs/showcase/P4-설계.md 1절, approval Q-25). */
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

export const PRESETS: Readonly<Record<'night' | 'incident' | 'monthEnd', Selection>> = {
  night: { employee: 'adm-a', slot: 'DAWN', items: 4831, ticket: 'NONE', device: 'USUAL' },
  incident: { employee: 'adm-a', slot: 'EVENING', items: 480, ticket: 'MATCH', device: 'USUAL' },
  monthEnd: { employee: 'eng-k', slot: 'AFTERNOON', items: 4831, ticket: 'NONE', device: 'USUAL' },
};

export function keyOf(selection: Selection): string {
  return [selection.employee, selection.slot, selection.items, selection.ticket, selection.device].join('.');
}

/** The selection a grid key names; null for anything that is not a grid cell. */
export function selectionOf(key: string): Selection | null {
  const [employee, slot, items, ticket, device] = key.split('.');
  if (
    !employee ||
    !(EMPLOYEES as readonly string[]).includes(employee) ||
    !SLOTS.includes(slot as Slot) ||
    !(ITEMS as readonly number[]).includes(Number(items)) ||
    !TICKETS.includes(ticket as TicketState) ||
    !DEVICES.includes(device as DeviceState)
  ) {
    return null;
  }
  return {
    employee,
    slot: slot as Slot,
    items: Number(items),
    ticket: ticket as TicketState,
    device: device as DeviceState,
  };
}

export function presetOf(selection: Selection): keyof typeof PRESETS | null {
  const key = keyOf(selection);
  const match = (Object.keys(PRESETS) as (keyof typeof PRESETS)[]).find((name) => keyOf(PRESETS[name]) === key);
  return match ?? null;
}
