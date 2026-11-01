import { describe, expect, it } from 'vitest';
import { factKey } from './factKey';

describe("a decision prompt line's entry", () => {
  it('reads a numbered line by its entry and a line the dictionary does not list as other', () => {
    expect(factKey('PastRecord3')).toBe('PastRecord');
    expect(factKey('PastRecordCounts')).toBe('PastRecordCounts');
    expect(factKey('UntrustedText12')).toBe('UntrustedText');
    expect(factKey('UntrustedTextX')).toBe('other');
    expect(factKey('Nonsense')).toBe('other');
  });
});
