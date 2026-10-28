export type OwnTrack = 'A' | 'H';

const KEY = 'contexa.journey.track';

/**
 * The track the visitor last stood on in this browser session. The evidence, the rules, the map and the wrap-up belong to
 * both tracks, so a visitor on one of them stands on a screen of no track; the screens that lead back to a track's
 * next-chooser read it from here. Where the browser keeps no session storage nothing is remembered and those screens
 * lead to the start instead.
 */
export function rememberedTrack(): OwnTrack | null {
  try {
    const value = window.sessionStorage.getItem(KEY);
    return value === 'A' || value === 'H' ? value : null;
  } catch {
    return null;
  }
}

export function rememberTrack(track: OwnTrack): void {
  try {
    window.sessionStorage.setItem(KEY, track);
  } catch {
    // the screens work without it
  }
}
