import ROUTE from './route.json';
import TOPICS_SOURCE from './topics.json';

/**
 * The visitor's one way through the demo (docs/showcase/최종화면-구현계획.md 2절, F0-1, IN-6): seven groups of 25
 * addresses in one order, each group but the first and the last opened by its cover (T0). The order, each screen's number, type and
 * group live in route.json, which the automatic check (e2e/frame-audit.mjs) reads too, so the two cannot disagree.
 * The screens of "learn more" (/more) are walked by topic (topics.json): back and next stay inside the topic and its
 * end leads back to /more.
 */
export type Act = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;
/** One route only; the concept path is gone (decision 1 changed, plan 13). */
export type Route = 'DEFAULT';
/** The screen types of the plan (6절, 15절): each has one job and its own fixed zones. T0 is a group's cover. */
export type ScreenType = 'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'T5' | 'T6' | 'T7' | 'T8';

/**
 * The seven groups of the main flow, the progress bar under the top bar (F0-2; the insider's group 5 of IN-6). 0 marks
 * a "learn more" screen.
 */
export const GROUPS = [1, 2, 3, 4, 5, 6, 7] as const;
export type Group = (typeof GROUPS)[number];

/** The six differences every wrap-up collects (identity slide), in their numbering. */
export const DIFFERENCES = [1, 2, 3, 4, 5, 6] as const;
export type Difference = (typeof DIFFERENCES)[number];

export interface Screen {
  /** The route id, which also names the screen in the journey state the portal keeps. */
  readonly id: string;
  /**
   * The screen's number: on the main flow the group and the place in it (1-1 … 7-2, main.{number}.* hold its copy);
   * on a "learn more" screen the number its copy keys screen.{number}.* kept from the flow before.
   */
  readonly number: string;
  readonly path: string;
  /** The group: 1 to 7 on the main flow, 0 on a "learn more" screen. */
  readonly act: Act;
  readonly type: ScreenType;
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

/** The address steps of a try page (kept for the timing topic, which sends its request on the try's run step). */
export const EXPERIENCE_STEPS = ['scene', 'compare', 'predict', 'run', 'result', 'reason', 'after'] as const;

/** The main flow in order. */
export const DEFAULT_ROUTE: readonly Screen[] = ROUTE as readonly Screen[];

/** The topics of "learn more" in the hub's order. */
export const TOPICS: readonly Topic[] = TOPICS_SOURCE as readonly Topic[];

/** The hub of "learn more", where every topic ends. */
export const MORE_PATH = '/more';

/** The topic an address belongs to; null on the main flow and outside every topic. */
export function topicOf(path: string): Topic | null {
  return TOPICS.find((topic) => topic.screens.some((screen) => screen.path === path)) ?? null;
}

/** The order an address is walked in: the main flow, its topic, or none. */
function orderOf(path: string): readonly Screen[] {
  if (DEFAULT_ROUTE.some((screen) => screen.path === path)) {
    return DEFAULT_ROUTE;
  }
  return topicOf(path)?.screens ?? [];
}

/** The screen at an address, on the main flow or in a topic; null elsewhere (the lab, the benchmark …). */
export function screenAt(_route: Route, path: string): Screen | null {
  return orderOf(path).find((screen) => screen.path === path) ?? null;
}

/** The next screen in the same order; null at the end of the flow or of a topic. */
export function nextScreen(_route: Route, path: string): Screen | null {
  const order = orderOf(path);
  const index = order.findIndex((screen) => screen.path === path);
  return index < 0 || index + 1 >= order.length ? null : (order[index + 1] ?? null);
}

/** The screen before in the same order; null at the start of the flow or of a topic. */
export function previousScreen(_route: Route, path: string): Screen | null {
  const order = orderOf(path);
  const index = order.findIndex((screen) => screen.path === path);
  return index <= 0 ? null : (order[index - 1] ?? null);
}

/** The screens of one group in order. */
export function actScreens(act: Act): readonly Screen[] {
  return act === 0 ? [] : DEFAULT_ROUTE.filter((screen) => screen.act === act);
}

/** The first screen of a group: its cover (T0) where it has one. */
export function actStart(act: Group): Screen {
  const first = DEFAULT_ROUTE.find((screen) => screen.act === act);
  if (!first) {
    throw new Error(`Group ${act} has no screen`);
  }
  return first;
}

/** Where "skip this group" would lead from a cover: the next group's first screen; null elsewhere and on the last. */
export function skipTarget(_route: Route, path: string): Screen | null {
  const here = screenAt('DEFAULT', path);
  if (!here || here.type !== 'T0' || here.act === 0 || here.act >= GROUPS.length) {
    return null;
  }
  return actStart((here.act + 1) as Group);
}

/** The address shared from a screen: the screen's own address (one route, nothing to keep). */
export function shareAddress(_route: Route, path: string, origin: string): string {
  return `${origin}${path}`;
}
