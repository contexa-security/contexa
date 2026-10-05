/** Time on a scene before the next one plays by itself (deck p.10: scenes continue automatically). */
export const AUTO_ADVANCE_MS = 12_000;
export const TICK_MS = 200;

interface Playback {
  readonly index: number;
  readonly elapsed: number;
}

type PlaybackAction = { readonly type: 'tick'; readonly scenes: number } | { readonly type: 'go'; readonly index: number };

/** One tick moves the progress; a full scene time moves to the next scene; the last scene never advances. */
export function playback(state: Playback, action: PlaybackAction): Playback {
  if (action.type === 'go') {
    return { index: action.index, elapsed: 0 };
  }
  if (state.index >= action.scenes - 1) {
    return state;
  }
  const elapsed = state.elapsed + TICK_MS;
  return elapsed >= AUTO_ADVANCE_MS ? { index: state.index + 1, elapsed: 0 } : { index: state.index, elapsed };
}
