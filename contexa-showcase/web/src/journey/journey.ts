import type { TeaserKey } from '../api/teasers';

/**
 * The visitor's two routes through the demo (docs/showcase/화면설계서-v2-구현계획.md 4절, screen design v2.3 0-3): the
 * default route "try it yourself" in four acts, and the concept path in nine steps. Both list the same screens by
 * address; only the order, the progress display and the way to the next screen differ (D-33).
 */
export type Act = 1 | 2 | 3 | 4;
export type Route = 'DEFAULT' | 'INTRO';

/** The six differences every screen points at (identity slide), in their numbering. */
export const DIFFERENCES = [1, 2, 3, 4, 5, 6] as const;
export type Difference = (typeof DIFFERENCES)[number];

/** Minutes each act takes on the default route (screen design 0-3). */
export const ACT_MINUTES: Readonly<Record<Act, number>> = { 1: 3, 2: 3, 3: 4, 4: 3 };

export interface Screen {
  /** The design's slide id, which names the screen in the tracker and the copy source. */
  readonly id: string;
  readonly path: string;
  /** The act on the default route; null for a screen only the concept path or the lab and benchmark show. */
  readonly act: Act | null;
  /** The step of the concept path (1 to 9); null for a screen it does not show. */
  readonly conceptStep: number | null;
  /** The step inside an experience (0 situation … 6 follow-up), when the screen is one. */
  readonly experienceStep?: number;
  /** The teaser card at the end of the screen on the default route (0-3 table). */
  readonly teaser?: TeaserKey | 'G_LEARNED_FLOW' | 'DILEMMA_DIFFERENCES';
  /** The screen closes its act on the default route with the act-end card. */
  readonly actEnd?: true;
}

/** The experience's seven steps, the second bar shown inside a try (common-1). */
export const EXPERIENCE_STEPS = ['scene', 'compare', 'predict', 'run', 'result', 'reason', 'after'] as const;

/** The concept path's nine steps (journey slide, D-17). */
export const CONCEPT_STEPS = [
  'intro',
  'problem',
  'approaches',
  'how',
  'learning',
  'compare',
  'try',
  'summary',
  'deeper',
] as const;

const attacker = (step: number, teaser?: Screen['teaser']): Screen => ({
  id: `e1-${['scene', 'compare', 'predict', 'run', 'result', 'reason', 'after'][step]}`,
  path: `/try/attacker/${EXPERIENCE_STEPS[step]}`,
  act: 1,
  conceptStep: 7,
  experienceStep: step,
  ...(teaser ? { teaser } : {}),
});

const owner = (step: number, teaser?: Screen['teaser']): Screen => ({
  id: `e2-${['scene', 'compare', 'predict', 'run', 'result', 'reason', 'check'][step]}`,
  path: `/try/owner/${EXPERIENCE_STEPS[step]}`,
  act: 2,
  conceptStep: 7,
  experienceStep: step,
  ...(teaser ? { teaser } : {}),
});

/** The default route in order (4.1 of the plan). */
export const DEFAULT_ROUTE: readonly Screen[] = [
  { id: 'hook', path: '/', act: 1, conceptStep: null, teaser: 'HOOK_TRY' },
  attacker(0),
  attacker(1),
  attacker(2),
  attacker(3),
  attacker(4, 'E1_RESULT_FACTS'),
  attacker(5, 'E1_REASON_MAILBOX'),
  attacker(6),
  // The act-end card is a screen of its own after the follow-up (D-41); its next act's teaser is the 0-3 table's.
  {
    id: 'act-end-1',
    path: '/try/attacker/end',
    act: 1,
    conceptStep: null,
    teaser: 'E1_AFTER_RULES',
    actEnd: true,
  },
  owner(0),
  owner(1),
  owner(2),
  owner(3),
  owner(4, 'E2_RESULT_DIFF'),
  owner(5),
  { id: 'g-rules', path: '/intro/how/rules', act: 2, conceptStep: 4, teaser: 'G_RULES_RESUME' },
  owner(6),
  { id: 'follow', path: '/try/follow', act: 2, conceptStep: 7 },
  // The act-end card is a screen of its own after the follow-up map (D-41); its next act's teaser is the 0-3 table's.
  {
    id: 'act-end-2',
    path: '/try/follow/end',
    act: 2,
    conceptStep: null,
    teaser: 'FOLLOW_LEARNED',
    actEnd: true,
  },
  { id: 'g-learn-why', path: '/intro/learning', act: 3, conceptStep: 5, teaser: 'LEARN_WHY_TAUGHT' },
  { id: 'g-learned', path: '/intro/learning/learned', act: 3, conceptStep: 5, teaser: 'G_LEARNED_FLOW' },
  { id: 'g-how', path: '/intro/how', act: 3, conceptStep: 4, teaser: 'G_HOW_LINES' },
  { id: 'e1-prompt', path: '/try/prompt', act: 3, conceptStep: 7, teaser: 'E1_PROMPT_ASYNC' },
  { id: 'sync-concept', path: '/try/timing/concept', act: 3, conceptStep: 7 },
  { id: 'sync-try', path: '/try/timing/try', act: 3, conceptStep: 7 },
  { id: 'sync-compare', path: '/try/timing/compare', act: 3, conceptStep: 7 },
  { id: 'sync-when', path: '/try/timing/when', act: 3, conceptStep: 7, teaser: 'SYNC_WHEN_OBSERVATIONS' },
  { id: 'e3-stack', path: '/try/stack', act: 3, conceptStep: 7 },
  { id: 'learn-after', path: '/try/summary/learning', act: 3, conceptStep: 8 },
  // The act-end card is a screen of its own after learning (D-41); its next act's teaser is the 0-3 table's.
  {
    id: 'act-end-3',
    path: '/try/summary/learning/end',
    act: 3,
    conceptStep: null,
    teaser: 'LEARN_AFTER_FALSE_BLOCKS',
    actEnd: true,
  },
  { id: 'g3-five', path: '/intro/approaches', act: 4, conceptStep: 3 },
  { id: 'g-where', path: '/intro/approaches/where', act: 4, conceptStep: 3, teaser: 'G_WHERE_C2' },
  { id: 'dilemma', path: '/try/summary/dilemma', act: 4, conceptStep: 8, teaser: 'DILEMMA_DIFFERENCES' },
  { id: 'recap', path: '/try/summary/recap', act: 4, conceptStep: 8 },
  { id: 'quiz', path: '/try/summary/quiz', act: 4, conceptStep: 8 },
  { id: 'value', path: '/try/summary/value', act: 4, conceptStep: 8 },
  { id: 'adopt-change', path: '/try/summary/adopt', act: 4, conceptStep: 8 },
];

const byId = new Map(DEFAULT_ROUTE.map((screen) => [screen.id, screen]));
const concept = (id: string, path: string, step: number): Screen => ({
  id,
  path,
  act: null,
  conceptStep: step,
});

/**
 * The concept path in order (journey slide, D-17): introduction, the problem, five approaches, how it judges, prior
 * learning, how we compare, the three tries, the wrap-up, and further.
 */
export const INTRO_ROUTE: readonly Screen[] = [
  concept('g1-start', '/intro', 1),
  concept('g2-concept', '/intro/concept', 2),
  { ...must('g3-five'), conceptStep: 3 },
  { ...must('g-where'), conceptStep: 3 },
  must('g-how'),
  must('g-rules'),
  must('g-learn-why'),
  must('g-learned'),
  concept('g4-compare', '/intro/compare', 6),
  concept('g5-order', '/intro/order', 6),
  // Try 1 with the prompt between its reasons and its follow-up, then the follow-up map (journey slide).
  ...DEFAULT_ROUTE.filter(
    (screen) => screen.act === 1 && !['hook', 'e1-after', 'act-end-1'].includes(screen.id),
  ),
  must('e1-prompt'),
  must('e1-after'),
  must('follow'),
  must('sync-concept'),
  must('sync-try'),
  must('sync-compare'),
  must('sync-when'),
  ...DEFAULT_ROUTE.filter((screen) => screen.act === 2 && screen.id.startsWith('e2-')),
  must('e3-stack'),
  must('learn-after'),
  must('dilemma'),
  must('recap'),
  must('quiz'),
  must('value'),
  must('adopt-change'),
  concept('lab', '/lab', 9),
  concept('benchmark', '/benchmark', 9),
];

function must(id: string): Screen {
  const screen = byId.get(id);
  if (!screen) {
    throw new Error(`Unknown screen ${id}`);
  }
  return screen;
}

export function routeOf(route: Route): readonly Screen[] {
  return route === 'INTRO' ? INTRO_ROUTE : DEFAULT_ROUTE;
}

/**
 * The route a screen is seen on (D-33, D-37): the address's own ?route=intro or ?route=default first; otherwise a
 * screen only one route lists belongs to that route (the hook to the default route, the introduction to the concept
 * path); only a screen both routes share keeps the stored route.
 */
export function routeAt(path: string, asked: string | null, stored: Route): Route {
  if (asked === 'intro') {
    return 'INTRO';
  }
  if (asked === 'default') {
    return 'DEFAULT';
  }
  const onDefault = DEFAULT_ROUTE.some((screen) => screen.path === path);
  const onIntro = INTRO_ROUTE.some((screen) => screen.path === path);
  if (onDefault !== onIntro) {
    return onDefault ? 'DEFAULT' : 'INTRO';
  }
  return stored;
}

/** The screen at an address on a route; null for an address the route does not list. */
export function screenAt(route: Route, path: string): Screen | null {
  return routeOf(route).find((screen) => screen.path === path) ?? null;
}

/** The next screen on the route; null at its end. */
export function nextScreen(route: Route, path: string): Screen | null {
  const screens = routeOf(route);
  const index = screens.findIndex((screen) => screen.path === path);
  return index < 0 || index + 1 >= screens.length ? null : (screens[index + 1] ?? null);
}

/**
 * The screens of one act on the default route, in order: the steps the place band shows under the current act, so the
 * band names exactly the screens the visitor walks through (2026-10-08: the try's seven steps left out the published
 * rules and the follow-up map, so the band and the "next" button disagreed).
 */
export function actScreens(act: Act): readonly Screen[] {
  return DEFAULT_ROUTE.filter((screen) => screen.act === act);
}

/** The screen before on the route: the action area's way back, so it names the same step the place band shows. */
export function previousScreen(route: Route, path: string): Screen | null {
  const screens = routeOf(route);
  const index = screens.findIndex((screen) => screen.path === path);
  return index <= 0 ? null : (screens[index - 1] ?? null);
}

/** The first screen of an act on the default route: where a past act's segment and "skip" lead. */
export function actStart(act: Act): Screen {
  const first = DEFAULT_ROUTE.find((screen) => screen.act === act);
  if (!first) {
    throw new Error(`Act ${act} has no screen`);
  }
  return first;
}

/** Where "skip" leads: the next act's start on the default route, the next concept step on the concept path. */
export function skipTarget(route: Route, path: string): Screen | null {
  const screens = routeOf(route);
  const index = screens.findIndex((screen) => screen.path === path);
  const here = screens[index];
  if (!here) {
    return null;
  }
  if (route === 'DEFAULT') {
    return here.act !== null && here.act < 4 ? actStart((here.act + 1) as Act) : null;
  }
  return (
    screens.slice(index + 1).find((screen) => (screen.conceptStep ?? 0) > (here.conceptStep ?? 0)) ?? null
  );
}

/**
 * The address shared from a screen keeps the route (D-37): a concept-path screen is shared with ?route=intro, so the
 * person who opens it continues on the same route.
 */
export function shareAddress(route: Route, path: string, origin: string): string {
  return `${origin}${path}${route === 'INTRO' ? '?route=intro' : ''}`;
}
