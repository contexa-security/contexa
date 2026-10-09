/**
 * Which screen's code an address opens first and which records its first render reads (C-13), one rule for the
 * application and the build: src/screens.tsx reads them before the first render, and firstScreenPreload.ts writes the
 * same rule into index.html so the browser starts reading them together with the application's code instead of after
 * it has run. Free of imports so the build can read it.
 */

/** Address beginnings, checked first, in this order. */
export const FIRST_SCREEN_PREFIXES = [
  ['/try/timing/', 'pages/try/TimingPage'],
  ['/try/follow', 'pages/try/FollowPage'],
] as const;

/** Whole addresses, checked next. */
export const FIRST_SCREEN_ADDRESSES = {
  '/intro/how/rules': 'pages/intro/RulesPage',
  '/intro/learning': 'pages/intro/LearnWhyPage',
  '/intro/learning/learned': 'pages/intro/LearnedPage',
  '/intro/how': 'pages/intro/HowPage',
  '/try/prompt': 'pages/try/PromptPage',
  '/try/stack': 'pages/try/StackPage',
  '/try/summary/learning': 'pages/try/LearnAfterPage',
  '/try/summary/learning/end': 'pages/try/LearnAfterPage',
  '/intro/approaches': 'pages/intro/ApproachesPage',
  '/intro/approaches/where': 'pages/intro/WherePage',
  '/try/summary/dilemma': 'pages/try/DilemmaPage',
  '/try/summary/recap': 'pages/try/RecapPage',
  '/try/summary/quiz': 'pages/try/QuizPage',
  '/try/summary/value': 'pages/try/ValuePage',
  '/try/summary/adopt': 'pages/try/AdoptChangePage',
  '/intro': 'pages/intro/IntroPage',
  '/intro/concept': 'pages/intro/ConceptPage',
  '/intro/compare': 'pages/intro/ComparePage',
  '/intro/order': 'pages/intro/OrderPage',
  '/lab': 'pages/lab/LabEntrancePage',
  '/lab/case': 'pages/lab/LabCasePage',
  '/lab/change': 'pages/lab/LabChangePage',
  '/lab/before': 'pages/lab/LabBeforePage',
  '/lab/send': 'pages/lab/LabSendPage',
  '/lab/result': 'pages/lab/LabResultPage',
  '/lab/rules': 'pages/lab/LabRulesPage',
} as const;

/** Address patterns as regular expression sources, checked last. */
export const FIRST_SCREEN_PATTERNS = [
  ['^/try/(attacker|owner)/[a-z]+$', 'pages/try/ExperiencePage'],
] as const;

export type FirstScreenModule =
  | (typeof FIRST_SCREEN_PREFIXES)[number][1]
  | (typeof FIRST_SCREEN_ADDRESSES)[keyof typeof FIRST_SCREEN_ADDRESSES]
  | (typeof FIRST_SCREEN_PATTERNS)[number][1];

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

/** The cases the tries of the default route send, by who the visitor is and the decision mode (7.1, 7.2, work 1). */
export const TRY_CASES = {
  attacker: { sync: 'A3', async: 'A3A' },
  owner: { sync: 'A3T', async: 'A3TA' },
} as const;

/**
 * The records a try step's head shows, read with its code: the case list on every step, and on the situation and the
 * comparison the latest run's comparison before sending for the step's case. The addresses are the ones the
 * application's queries ask (src/firstScreens.test.ts holds them together).
 */
export const FIRST_RECORDS = {
  pattern: '^/try/(attacker|owner)/([a-z]+)$',
  always: ['/api/lab/options'],
  compared: ['scene', 'compare'],
  comparison: '/api/live/before/{case}?step=1',
} as const;

/** The decision mode an address asks for: asynchronous only when it says so. */
export function modeOfSearch(search: string): 'sync' | 'async' {
  return new URLSearchParams(search).get('mode') === 'async' ? 'async' : 'sync';
}

/** The record addresses the first render of this address reads; none for the screens that show no records first. */
export function firstRecordsOf(pathname: string, search: string): string[] {
  const match = new RegExp(FIRST_RECORDS.pattern).exec(pathname);
  const role = match?.[1] === 'owner' ? 'owner' : match?.[1] === 'attacker' ? 'attacker' : null;
  const step = match?.[2] ?? '';
  if (role === null) {
    return [];
  }
  const records: string[] = [...FIRST_RECORDS.always];
  if ((FIRST_RECORDS.compared as readonly string[]).includes(step)) {
    const key = TRY_CASES[role][modeOfSearch(search)];
    records.push(FIRST_RECORDS.comparison.replace('{case}', encodeURIComponent(key)));
  }
  return records;
}
