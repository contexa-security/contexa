import LANES_SOURCE from './lanes.json';
import ROUTE from './route.json';
import TOPICS_SOURCE from './topics.json';

/**
 * The visitor's way through the demo (docs/showcase/첫화면-선택형-체험-개선기획안.md 4절, 구현계획 NW-1): a start that
 * makes the visitor choose a track, the agent's or the person's, each walked by its own lanes (the screens of one case
 * in order), then a next-chooser that offers the opposite scene, a change of condition, the deeper screens and the
 * wrap-up. The order of the screens of a lane, each screen's number, type, track and step live in route.json and the
 * lanes' ends in lanes.json, which the automatic checks (e2e) read too, so the two cannot disagree. The screens of
 * "learn more" (/more) are walked by topic (topics.json): back and next stay inside the topic and its end leads back
 * to /more.
 */
export type Act = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
/** One route only; the concept path is gone (decision 1 changed, plan 13). */
export type Route = 'DEFAULT';
/**
 * The screen types: each has one job and its own fixed zones (화면재편-기획안 6절). T9 is the choosing screen of the
 * choose-and-test design: a strong title, one intro line and cards to choose from.
 */
export type ScreenType = 'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'T5' | 'T6' | 'T7' | 'T8' | 'T9';
/** The agent's track, the person's track, or a screen both tracks share (the start, the deeper screens, the wrap-up). */
export type Track = 'A' | 'H' | 'C';

/** The steps of a track, shown as dots in the top bar: choose, predict, run, result, reason, next. */
export const STEPS = 6;

/** The six differences every wrap-up collects (identity slide), in their numbering. */
export const DIFFERENCES = [1, 2, 3, 4, 5, 6] as const;
export type Difference = (typeof DIFFERENCES)[number];

export interface Screen {
  /** The route id, which also names the screen in the journey state the portal keeps. */
  readonly id: string;
  /**
   * The screen's number: on the main flow its old plan number or, for a choosing screen, H-1, H-6, A-1, A-6 and D-1
   * (main.{number}.* hold its copy); on a "learn more" screen the number its copy keys screen.{number}.* kept.
   */
  readonly number: string;
  readonly path: string;
  /** The group the portal stores: 0 to 8; 0 marks a "learn more" screen. */
  readonly act: Act;
  readonly type: ScreenType;
  /** The track of a main-flow screen. */
  readonly track?: Track;
  /** The lane of a main-flow screen: the screens of one case, walked in the order route.json lists them. */
  readonly lane?: string;
  /** The step of six the top bar marks; null on a screen outside the steps of a track. */
  readonly step?: number | null;
  /** The headline is the sentence the server picks from the result (results), not a fixed key. */
  readonly serverTitle?: boolean;
  /** The guide line follows the engine's judgment. */
  readonly serverGuide?: boolean;
  /** Keys of the other guide lines the screen may show instead. */
  readonly guideAlternatives?: readonly string[];
  /** Keys of the other headlines the screen may show instead. */
  readonly titleAlternatives?: readonly string[];
}

/** A topic of "learn more": its screens in order (최종화면-구현계획 2절). */
export interface Topic {
  readonly id: string;
  readonly screens: readonly Screen[];
}

/** Where a lane begins and ends: the screen before its first one and the one after its last (with what it carries). */
interface Lane {
  readonly id: string;
  readonly before: string | null;
  readonly after: { readonly to: string; readonly from?: string } | null;
}

/** The address steps of a try page (kept for the timing topic, which sends its request on the try's run step). */
export const EXPERIENCE_STEPS = ['scene', 'compare', 'predict', 'run', 'result', 'reason', 'after'] as const;

/** The main flow: every screen, grouped by lane in the order a lane is walked. */
export const DEFAULT_ROUTE: readonly Screen[] = ROUTE as readonly Screen[];

const LANES: readonly Lane[] = LANES_SOURCE as readonly Lane[];

/** The topics of "learn more" in the hub's order. */
export const TOPICS: readonly Topic[] = TOPICS_SOURCE as readonly Topic[];

/** The hub of "learn more", where every topic ends. */
export const MORE_PATH = '/more';

/**
 * The addresses of the old covers, which no longer are screens: they lead to the first screen of what they opened, so a
 * link shared before keeps working (구현계획 3절).
 */
export const COVER_REDIRECTS: Readonly<Record<string, string>> = {
  '/attack': '/attack/request',
  '/normal': '/normal/request',
  '/insider': '/insider/request',
  '/evidence': '/evidence/map',
  '/compare': '/compare/rule',
};

/** The topic an address belongs to; null on the main flow and outside every topic. */
export function topicOf(path: string): Topic | null {
  return TOPICS.find((topic) => topic.screens.some((screen) => screen.path === path)) ?? null;
}

/** The order an address is walked in: its lane on the main flow, its topic, or none. */
function orderOf(path: string): readonly Screen[] {
  const here = DEFAULT_ROUTE.find((screen) => screen.path === path);
  if (here) {
    return DEFAULT_ROUTE.filter((screen) => screen.lane === here.lane);
  }
  return topicOf(path)?.screens ?? [];
}

/** The lane an address is walked in; null for a screen of a topic and outside the flow. */
function laneOf(path: string): Lane | null {
  const here = DEFAULT_ROUTE.find((screen) => screen.path === path);
  return LANES.find((lane) => lane.id === here?.lane) ?? null;
}

/** The screen at an address, on the main flow or in a topic; null elsewhere (the lab, the benchmark …). */
export function screenAt(_route: Route, path: string): Screen | null {
  return orderOf(path).find((screen) => screen.path === path) ?? null;
}

/**
 * The next screen: the next of the same lane, or, after the last of a lane, the screen the lane leads to (with the
 * lane it came from in the query, so the next-chooser can offer the opposite scene); null at the end of a lane that
 * leads nowhere and of a topic.
 */
export function nextScreen(_route: Route, path: string): Screen | null {
  const order = orderOf(path);
  const index = order.findIndex((screen) => screen.path === path);
  if (index < 0) {
    return null;
  }
  const following = order[index + 1];
  if (following) {
    return following;
  }
  const after = laneOf(path)?.after;
  const target = after ? screenAt('DEFAULT', after.to) : null;
  return target && after
    ? { ...target, path: after.from ? `${target.path}?from=${after.from}` : target.path }
    : null;
}

/** The screen before: the one before in the lane, or, before the first of a lane, the screen the lane begins from. */
export function previousScreen(_route: Route, path: string): Screen | null {
  const order = orderOf(path);
  const index = order.findIndex((screen) => screen.path === path);
  if (index < 0) {
    return null;
  }
  const before = order[index - 1];
  if (before) {
    return before;
  }
  const start = laneOf(path)?.before;
  return start ? screenAt('DEFAULT', start) : null;
}

/** The track of a main-flow address; null elsewhere. */
export function trackOf(path: string): Track | null {
  return DEFAULT_ROUTE.find((screen) => screen.path === path)?.track ?? null;
}

/** The first screen of a track: the chooser the visitor picks a case on. */
export function entryOf(track: Exclude<Track, 'C'>): string {
  return track === 'A' ? '/agent' : '/person';
}

/** The other track: the agent's for the person's and the person's for the agent's. */
export function otherTrack(track: Exclude<Track, 'C'>): Exclude<Track, 'C'> {
  return track === 'A' ? 'H' : 'A';
}

/** The address shared from a screen: the screen's own address (one route, nothing to keep). */
export function shareAddress(_route: Route, path: string, origin: string): string {
  return `${origin}${path}`;
}
