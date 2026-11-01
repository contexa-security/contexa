import { useCallback, useState } from 'react';

/**
 * Dark by default, light on request (기획안 6.2, DEC-5). The choice is kept in the browser; when the storage is
 * unavailable (a private window, blocked site data) the page still draws, in dark. index.html applies the stored theme
 * before the first paint with the same key.
 */
export type Theme = 'dark' | 'light';

export const THEME_STORAGE_KEY = 'showcase.theme';

export function readTheme(): Theme {
  try {
    return window.localStorage.getItem(THEME_STORAGE_KEY) === 'light' ? 'light' : 'dark';
  } catch {
    return 'dark';
  }
}

export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme);
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // The theme still applies to this page; it is only not remembered.
  }
}

export function useTheme(): { readonly theme: Theme; readonly toggle: () => void } {
  const [theme, setTheme] = useState<Theme>(readTheme);
  const toggle = useCallback(() => {
    const next: Theme = theme === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    setTheme(next);
  }, [theme]);
  return { theme, toggle };
}
