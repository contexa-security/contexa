import { useSyncExternalStore } from 'react';

/** The phone width of the tokens (`width <= 40rem`), where a chart gives way to cards. */
const NARROW = '(width <= 40rem)';

function subscribe(onChange: () => void): () => void {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return () => undefined;
  }
  const query = window.matchMedia(NARROW);
  query.addEventListener('change', onChange);
  return () => query.removeEventListener('change', onChange);
}

function narrowNow(): boolean {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function'
    ? window.matchMedia(NARROW).matches
    : false;
}

/** Whether the page is at phone width; a page without media queries (a test) is wide. */
export function useNarrow(): boolean {
  return useSyncExternalStore(subscribe, narrowNow, () => false);
}
