import { useQuery } from '@tanstack/react-query';
import { getJson } from './http';

/**
 * A recorded guide video as the build placed it (가이드영상-계획.md 5절): its file, its caption tracks by language, its
 * measured length and when and from which screens it was recorded.
 */
export interface GuideVideo {
  readonly file: string;
  readonly captions: Readonly<Record<string, string>>;
  readonly durationSec: number;
  readonly recordedAt: string;
  readonly screens: string;
}

/** The recorded guide videos by id, from the manifest the recording script writes next to them. */
export function useGuides() {
  return useQuery({
    queryKey: ['guides'],
    queryFn: () => getJson<Readonly<Record<string, GuideVideo>>>('/guides/guides.json'),
    staleTime: Infinity,
    retry: false,
  });
}
