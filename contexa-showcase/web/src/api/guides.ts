import { useQuery } from '@tanstack/react-query';
import { getJson } from './http';

/** A scene of a recorded guide video: the dictionary key of its line and the second it starts at. */
export interface GuideScene {
  readonly key: string;
  readonly start: number;
}

/**
 * A recorded guide video as the build placed it (가이드영상-제작기획안.md 7.1절): its file, its caption tracks by
 * language (and the ones cut for a phone, which has fewer characters to a line), its measured length, its scenes and when
 * and from which screens it was recorded.
 */
export interface GuideVideo {
  readonly file: string;
  readonly captions: Readonly<Record<string, string>>;
  readonly captionsNarrow?: Readonly<Record<string, string>>;
  readonly durationSec: number;
  readonly recordedAt: string;
  readonly screens: string;
  readonly scenes?: readonly GuideScene[];
}

/**
 * A guide as the manifest lists it: one recording per language (the screen's words are in the video, so a Korean screen
 * shows the Korean recording), or, for a recording made before that, one that serves both.
 */
export type GuideRecording = GuideVideo | Readonly<Partial<Record<'ko' | 'en', GuideVideo>>>;

export type GuideManifest = Readonly<Record<string, GuideRecording>>;

/** The video of a guide in a language; none when that language was not recorded (the link is not drawn then). */
export function videoOf(
  manifest: GuideManifest | undefined,
  id: string,
  language: 'ko' | 'en',
): GuideVideo | undefined {
  const entry = manifest?.[id];
  if (entry === undefined) {
    return undefined;
  }
  return 'file' in entry ? entry : entry[language];
}

/** The recorded guide videos by id, from the manifest the recording script writes next to them. */
export function useGuides() {
  return useQuery({
    queryKey: ['guides'],
    queryFn: () => getJson<GuideManifest>('/guides/guides.json'),
    staleTime: Infinity,
    retry: false,
  });
}
