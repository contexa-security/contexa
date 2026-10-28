import route from '../../journey/route.json';
import guides from './guides.json';

/** One guide video of docs/showcase/가이드영상-제작기획안.md 3.3절 as the site knows it. */
export interface GuideEntry {
  /** Which part of the plan it belongs to: the eleven required, the four recommended, or one recorded before the new flow. */
  readonly kind: 'required' | 'recommended' | 'legacy';
  /** The dictionary key of its title. */
  readonly title: string;
  /** The screens that carry its link: a journey screen's number, or 'benchmark' / 'lab' for the places outside the 34. */
  readonly screens: readonly string[];
  /** The dictionary keys of its scene lines, in the order shown; written with the scene drafts (plan VP-7). */
  readonly scenes: readonly string[];
}

export type GuideId = keyof typeof guides;

const ENTRIES = guides as Readonly<Record<GuideId, GuideEntry>>;

/** Every guide id in the plan's order: required, recommended, then the old ones. */
export const GUIDE_IDS = Object.keys(ENTRIES) as readonly GuideId[];

export function guideEntry(id: GuideId): GuideEntry {
  return ENTRIES[id];
}

export function guidesOfKind(kind: GuideEntry['kind']): GuideId[] {
  return GUIDE_IDS.filter((id) => ENTRIES[id].kind === kind);
}

/** Where a video is listed: the newcomer's own group, or the track (person, agent, shared) of its first screen. */
export type GuideGroup = 'S' | 'H' | 'A' | 'C';

export function guideGroup(id: GuideId): GuideGroup {
  if (id === 'start') {
    return 'S';
  }
  const first = ENTRIES[id].screens[0];
  const track = route.find((screen) => screen.number === first)?.track;
  return track === 'H' || track === 'A' ? track : 'C';
}

/** The address of a screen a video explains, by its number; 'benchmark' and 'lab' are the places outside the journey. */
export function guideScreenPath(screen: string): string | null {
  if (screen === 'benchmark' || screen === 'lab') {
    return `/${screen}`;
  }
  return route.find((found) => found.number === screen)?.path ?? null;
}

/** The guide whose link a screen carries, by the screen's number; null for a screen without a video. */
export function guideForScreen(screen: string | null | undefined): GuideId | null {
  if (!screen) {
    return null;
  }
  return GUIDE_IDS.find((id) => ENTRIES[id].screens.includes(screen)) ?? null;
}
