import { videoOf, type GuideManifest, type GuideVideo } from '../../../api/guides';

/**
 * The screens the guide videos are recorded on now: a recording of any other screens predates the redesign and is
 * marked so (DEC-68). The recording script writes this value into the manifest when the videos are recorded again.
 */
export const CURRENT_SCREENS = 'ux-r1';

export type Video = GuideVideo & { readonly id: string };

/** The videos a visitor can watch in a language: a recording per language, or one that serves both (ST-84). */
export function videosIn(manifest: GuideManifest | undefined, language: 'ko' | 'en'): readonly Video[] {
  return Object.keys(manifest ?? {}).flatMap((id) => {
    const video = videoOf(manifest, id, language);
    return video ? [{ ...video, id }] : [];
  });
}

/** `70.1` → `1:10`, the way a player writes a time. */
export function clock(seconds: number): string {
  const whole = Math.floor(seconds);
  return `${Math.floor(whole / 60)}:${String(whole % 60).padStart(2, '0')}`;
}
