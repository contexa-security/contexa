import { describe, expect, it } from 'vitest';
import { formatDuration, formatNumber, formatSeconds, formatUtc, localTime } from './format';

describe('format', () => {
  it('groups thousands by the language', () => {
    expect(formatNumber(13733, 'ko')).toBe('13,733');
    expect(formatNumber(13733, 'en')).toBe('13,733');
    expect(formatNumber(0.4321, 'en', 2)).toBe('0.43');
  });

  it('writes a recorded time in UTC as YYYY-MM-DD HH:mm', () => {
    expect(formatUtc('2026-10-31T15:24:09.512Z')).toBe('2026-10-31 15:24');
    expect(formatUtc('2026-11-01T00:05:00+09:00')).toBe('2026-10-31 15:05');
    expect(formatUtc('not a time')).toBe('—');
  });

  it('keeps the local time for the tooltip', () => {
    expect(localTime('2026-10-31T15:24:00Z', 'ko')).toMatch(/2026/);
    expect(localTime('nope', 'en')).toBe('');
  });

  it('writes a latency in seconds with one decimal', () => {
    expect(formatSeconds(5959, 'ko')).toBe('6.0');
    expect(formatSeconds(16321, 'en')).toBe('16.3');
  });

  it('writes a response time with three decimals under a second and one above', () => {
    expect(formatDuration(27, 'ko')).toBe('0.027');
    expect(formatDuration(10169, 'en')).toBe('10.2');
  });
});
