import { describe, expect, it } from 'vitest';
import type { LabConditions } from '../api/lab';
import { compareConditions } from './pairs';

const attack: LabConditions = {
  employee: 'adm-a',
  timeSlot: 'DAWN',
  place: 'OFFICE',
  device: 'USUAL',
  operation: 'EXPORT',
  target: 'UNASSIGNED',
  items: 4831,
  approval: false,
  ticket: 'NONE',
  claim: 'NONE',
  onCall: false,
};

describe('the conditions of a pair', () => {
  it('lists what the two cases share and what they do not, and says when only the records differ', () => {
    const comparison = compareConditions(attack, { ...attack, approval: true });
    expect(comparison.different).toEqual(['approval']);
    expect(comparison.same).toContain('timeSlot');
    expect(comparison.recordsOnly).toBe(true);
  });

  it('does not claim the requests look the same when the request itself differs', () => {
    const comparison = compareConditions(attack, { ...attack, place: 'TRAVEL', device: 'NEW' });
    expect(comparison.different).toEqual(['place', 'device']);
    expect(comparison.recordsOnly).toBe(false);
  });

  it('leaves out a condition a case leaves open', () => {
    const comparison = compareConditions({ ...attack, items: null }, attack);
    expect(comparison.same).not.toContain('items');
    expect(comparison.different).not.toContain('items');
  });
});
