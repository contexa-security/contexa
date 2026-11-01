import { useCallback, useSyncExternalStore } from 'react';

/**
 * The menu's three widths (기획안 4.2): the full side menu from 1280, the icon rail from 1024 to 1279, the drawer below
 * 1024. A page without media queries (a test) is wide.
 */
export const RAIL_QUERY = '(1024px <= width < 1280px)';
export const DRAWER_QUERY = '(width < 1024px)';

function matches(query: string): boolean {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function'
    ? window.matchMedia(query).matches
    : false;
}

export function useMedia(query: string): boolean {
  const subscribe = useCallback(
    (onChange: () => void) => {
      if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
        return () => undefined;
      }
      const list = window.matchMedia(query);
      list.addEventListener('change', onChange);
      return () => list.removeEventListener('change', onChange);
    },
    [query],
  );
  return useSyncExternalStore(
    subscribe,
    () => matches(query),
    () => false,
  );
}
