import { useSyncExternalStore } from 'react';

/** Which guide videos this browser played to the end: kept in this browser only, never sent anywhere (plan 4.2절, D-7). */
const KEY = 'contexa.guide.watched';
const CHANGED = 'contexa-guide-watched';

function read(): readonly string[] {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(KEY) ?? '[]');
    return Array.isArray(parsed) ? parsed.filter((id): id is string => typeof id === 'string') : [];
  } catch {
    // A browser that blocks its storage simply keeps no mark.
    return [];
  }
}

export function markWatched(id: string): void {
  const now = read();
  if (now.includes(id)) {
    return;
  }
  try {
    window.localStorage.setItem(KEY, JSON.stringify([...now, id]));
  } catch {
    return;
  }
  window.dispatchEvent(new Event(CHANGED));
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener(CHANGED, onChange);
  window.addEventListener('storage', onChange);
  return () => {
    window.removeEventListener(CHANGED, onChange);
    window.removeEventListener('storage', onChange);
  };
}

/** Whether the guide was watched to the end in this browser. */
export function useWatched(id: string): boolean {
  return useSyncExternalStore(
    subscribe,
    () => read().includes(id),
    () => false,
  );
}
