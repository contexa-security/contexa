import { describe, expect, it } from 'vitest';
import { ageOf } from './menuAge';

const NOW = Date.parse('2026-10-27T12:00:00Z');

describe('how old a stored real run is (AC-4a)', () => {
  it('counts hours below two days and days from then on', () => {
    expect(ageOf('2026-10-27T11:50:00Z', NOW)).toEqual({ unit: 'now', n: 0 });
    expect(ageOf('2026-10-27T11:00:00Z', NOW)).toEqual({ unit: 'hours', n: 1 });
    expect(ageOf('2026-10-27T07:20:00Z', NOW)).toEqual({ unit: 'hours', n: 4 });
    expect(ageOf('2026-10-25T13:00:00Z', NOW)).toEqual({ unit: 'hours', n: 47 });
    expect(ageOf('2026-10-25T12:00:00Z', NOW)).toEqual({ unit: 'days', n: 2 });
    expect(ageOf('2026-10-20T11:00:00Z', NOW)).toEqual({ unit: 'days', n: 7 });
  });

  it('never goes negative when the portal clock is ahead of the browser', () => {
    expect(ageOf('2026-10-27T12:30:00Z', NOW)).toEqual({ unit: 'now', n: 0 });
  });
});
