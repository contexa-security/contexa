import type { StreamProgress, StreamSample } from '../api/types';

/**
 * Stream exposure from the stored samples (deck p.11). Nothing is interpolated: the count shown at a moment is the
 * last recorded sample at or before it.
 */
export function itemsAt(samples: readonly StreamSample[], ms: number): number {
  let items = 0;
  for (const [atMs, count] of samples) {
    if (atMs > ms) {
      break;
    }
    items = count;
  }
  return items;
}

/** Seconds during which items were leaving: from the first item to the end, cut or break. */
export function exposureSeconds(stream: StreamProgress): number {
  return stream.firstLineMs === null ? 0 : Math.max(0, stream.endMs - stream.firstLineMs) / 1000;
}

export type StreamState = 'cut' | 'interrupted' | 'done';

export function streamState(stream: StreamProgress): StreamState {
  return stream.cut ? 'cut' : stream.interrupted ? 'interrupted' : 'done';
}
