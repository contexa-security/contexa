import { describe, expect, it } from 'vitest';
import { decisionMix, percent, seconds, utcMinute } from './stats';

describe('execution statistics formatting', () => {
  it('never turns an empty count into 0%', () => {
    expect(percent(0, 0)).toBeNull();
    expect(percent(0, 4)).toBe(0);
    expect(percent(1, 3)).toBe(33);
    expect(percent(2, 3)).toBe(67);
  });

  it('splits the resolved decisions in a fixed order and keeps empty actions in the legend', () => {
    const mix = decisionMix({ ALLOW: 2, CHALLENGE: 1, BLOCK: 1, ESCALATE: 0 });
    expect(mix.total).toBe(4);
    expect(mix.segments.map((segment) => [segment.action, segment.count, segment.share])).toEqual([
      ['ALLOW', 2, 50],
      ['CHALLENGE', 1, 25],
      ['BLOCK', 1, 25],
      ['ESCALATE', 0, 0],
    ]);
    expect(
      decisionMix({ ALLOW: 0, CHALLENGE: 0, BLOCK: 0, ESCALATE: 0 }).segments.every((s) => s.share === 0),
    ).toBe(true);
  });

  it('shows times in seconds and instants in UTC', () => {
    expect(seconds(2500)).toBe('2.5');
    expect(seconds(null)).toBeNull();
    expect(utcMinute('2026-10-05T07:30:12.345Z')).toBe('2026-10-05 07:30 UTC');
  });
});
