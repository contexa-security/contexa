import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { THEME_STORAGE_KEY, applyTheme, readTheme, useTheme } from './theme';

afterEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
  vi.restoreAllMocks();
});

describe('theme', () => {
  it('starts dark and keeps the stored choice', () => {
    expect(readTheme()).toBe('dark');
    window.localStorage.setItem(THEME_STORAGE_KEY, 'light');
    expect(readTheme()).toBe('light');
    window.localStorage.setItem(THEME_STORAGE_KEY, 'sepia');
    expect(readTheme()).toBe('dark');
  });

  it('still draws dark when the storage is unavailable', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    expect(readTheme()).toBe('dark');
  });

  it('sets the page theme and stores it, and the hook toggles it', () => {
    applyTheme('light');
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe('light');
    act(() => result.current.toggle());
    expect(result.current.theme).toBe('dark');
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark');
  });
});
