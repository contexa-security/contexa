import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { rememberedTrack, rememberTrack } from './trackMemory';

beforeEach(() => {
  window.sessionStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('the track the visitor was last on', () => {
  it('is none before the visitor stood on a track', () => {
    expect(rememberedTrack()).toBeNull();
  });

  it('is the last track remembered', () => {
    rememberTrack('H');
    expect(rememberedTrack()).toBe('H');
    rememberTrack('A');
    expect(rememberedTrack()).toBe('A');
  });

  it('ignores a value that is no track', () => {
    window.sessionStorage.setItem('contexa.journey.track', 'C');
    expect(rememberedTrack()).toBeNull();
  });

  it('works without session storage: nothing is remembered and nothing breaks', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    expect(() => rememberTrack('H')).not.toThrow();
    expect(rememberedTrack()).toBeNull();
  });
});
