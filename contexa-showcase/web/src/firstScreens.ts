/**
 * Which screen's code an address opens first and which records its first render reads (C-13), one rule for the
 * application and the build: src/screens.tsx reads them before the first render, and firstScreenPreload.ts writes the
 * same rule into index.html so the browser starts reading them together with the application's code instead of after
 * it has run. Free of imports so the build can read it.
 *
 * UX-R1 (구현계획서 DEC-14, DEC-76): the first screens are the introduction, the start of the demo and the threat
 * simulation's steps; the old
 * screens have no address of their own any more (their addresses lead to the new places).
 */

/** Whole addresses, checked first. */
export const FIRST_SCREEN_ADDRESSES = {
  '/': 'ux/pages/intro/IntroPage',
  '/start': 'ux/pages/home/HomePage',
  '/simulate/person': 'ux/pages/simulate/person/PickPage',
} as const;

/** Address patterns as regular expression sources, checked next. */
export const FIRST_SCREEN_PATTERNS = [
  ['^/simulate/person/(S13|S13T|S16)/review$', 'ux/pages/simulate/person/ReviewPage'],
  ['^/simulate/person/(S13|S13T|S16)/live$', 'ux/pages/simulate/person/LivePage'],
  ['^/simulate/person/(S13|S13T|S16)/result$', 'ux/pages/simulate/person/ResultPage'],
] as const;

export type FirstScreenModule =
  | (typeof FIRST_SCREEN_ADDRESSES)[keyof typeof FIRST_SCREEN_ADDRESSES]
  | (typeof FIRST_SCREEN_PATTERNS)[number][1];

/** Address beginnings, checked before the rest; none now (kept for the rule's shape). */
export const FIRST_SCREEN_PREFIXES: readonly (readonly [string, FirstScreenModule])[] = [];

/** The screen module the address opens, as a path under src without its extension; null for the other addresses. */
export function firstScreenOf(pathname: string): FirstScreenModule | null {
  for (const [start, module] of FIRST_SCREEN_PREFIXES) {
    if (pathname.startsWith(start)) {
      return module;
    }
  }
  if (Object.prototype.hasOwnProperty.call(FIRST_SCREEN_ADDRESSES, pathname)) {
    return FIRST_SCREEN_ADDRESSES[pathname as keyof typeof FIRST_SCREEN_ADDRESSES];
  }
  for (const [source, module] of FIRST_SCREEN_PATTERNS) {
    if (new RegExp(source).test(pathname)) {
      return module;
    }
  }
  return null;
}

/**
 * The records the request review's first render shows, read with its code: the case list and the comparison before
 * sending of the address's scenario. The addresses are the ones the application's queries ask (src/firstScreens.test.ts
 * holds them together).
 */
export const FIRST_RECORDS = {
  pattern: '^/simulate/person/(S13|S13T|S16)/review$',
  always: ['/api/lab/options'],
  comparison: '/api/live/before/{case}?step=1',
} as const;

/** The record addresses the first render of this address reads; none for the screens that show no records first. */
export function firstRecordsOf(pathname: string): string[] {
  const match = new RegExp(FIRST_RECORDS.pattern).exec(pathname);
  if (!match?.[1]) {
    return [];
  }
  return [...FIRST_RECORDS.always, FIRST_RECORDS.comparison.replace('{case}', encodeURIComponent(match[1]))];
}

/**
 * The cases the old try steps sent, by who the visitor is and the decision mode; kept for the old try helpers
 * (src/pages/try/experience.ts) until the old files are removed.
 */
export const TRY_CASES = {
  attacker: { sync: 'A3', async: 'A3A' },
  owner: { sync: 'A3T', async: 'A3TA' },
} as const;

/** The decision mode an address asks for: asynchronous only when it says so (old try helpers). */
export function modeOfSearch(search: string): 'sync' | 'async' {
  return new URLSearchParams(search).get('mode') === 'async' ? 'async' : 'sync';
}
