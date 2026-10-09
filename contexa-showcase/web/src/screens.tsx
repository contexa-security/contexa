import type { QueryClient } from '@tanstack/react-query';
import { lazy, type ComponentType } from 'react';
import { beforeSendQuery } from './api/anatomy';
import { labOptionsQuery } from './api/lab';
import { firstScreenOf, type FirstScreenModule } from './firstScreens';
import { CASES, modeOf } from './pages/try/experience';

/**
 * A screen whose code loads when it is first opened (P5-FE-01), which a visitor can also open straight from a shared
 * step link. On such a first load its code is read before the first render, so the screen never waits behind the
 * loading fallback, which React keeps for at least 300 ms once shown (C-13).
 */
function preloadable<P extends object>(load: () => Promise<{ default: ComponentType<P> }>) {
  let loaded: ComponentType<P> | null = null;
  const Lazy = lazy(load);
  function Screen(props: P) {
    const Loaded = loaded;
    return Loaded ? <Loaded {...props} /> : <Lazy {...props} />;
  }
  return {
    Screen,
    preload: () =>
      load().then((module) => {
        loaded = module.default;
      }),
  };
}

export const experienceScreen = preloadable(() => import('./pages/try/ExperiencePage'));
export const followScreen = preloadable(() => import('./pages/try/FollowPage'));
export const rulesScreen = preloadable(() => import('./pages/intro/RulesPage'));
export const learnWhyScreen = preloadable(() => import('./pages/intro/LearnWhyPage'));
export const learnedScreen = preloadable(() => import('./pages/intro/LearnedPage'));
export const howScreen = preloadable(() => import('./pages/intro/HowPage'));
export const promptScreen = preloadable(() => import('./pages/try/PromptPage'));
export const timingScreen = preloadable(() => import('./pages/try/TimingPage'));
export const stackScreen = preloadable(() => import('./pages/try/StackPage'));
export const learnAfterScreen = preloadable(() => import('./pages/try/LearnAfterPage'));
export const approachesScreen = preloadable(() => import('./pages/intro/ApproachesPage'));
export const whereScreen = preloadable(() => import('./pages/intro/WherePage'));
export const dilemmaScreen = preloadable(() => import('./pages/try/DilemmaPage'));
export const recapScreen = preloadable(() => import('./pages/try/RecapPage'));
export const quizScreen = preloadable(() => import('./pages/try/QuizPage'));
export const valueScreen = preloadable(() => import('./pages/try/ValuePage'));
export const adoptChangeScreen = preloadable(() => import('./pages/try/AdoptChangePage'));
export const introScreen = preloadable(() => import('./pages/intro/IntroPage'));
export const conceptScreen = preloadable(() => import('./pages/intro/ConceptPage'));
export const compareScreen = preloadable(() => import('./pages/intro/ComparePage'));
export const orderScreen = preloadable(() => import('./pages/intro/OrderPage'));
export const labEntranceScreen = preloadable(() => import('./pages/lab/LabEntrancePage'));
export const labCaseScreen = preloadable(() => import('./pages/lab/LabCasePage'));
export const labChangeScreen = preloadable(() => import('./pages/lab/LabChangePage'));
export const labBeforeScreen = preloadable(() => import('./pages/lab/LabBeforePage'));
export const labSendScreen = preloadable(() => import('./pages/lab/LabSendPage'));
export const labResultScreen = preloadable(() => import('./pages/lab/LabResultPage'));
export const labRulesScreen = preloadable(() => import('./pages/lab/LabRulesPage'));

/** Each first screen's code, by the module the shared rule (src/firstScreens.ts) names. */
const BY_MODULE: Readonly<Record<FirstScreenModule, { readonly preload: () => Promise<void> }>> = {
  'pages/try/ExperiencePage': experienceScreen,
  'pages/try/TimingPage': timingScreen,
  'pages/try/FollowPage': followScreen,
  'pages/intro/RulesPage': rulesScreen,
  'pages/intro/LearnWhyPage': learnWhyScreen,
  'pages/intro/LearnedPage': learnedScreen,
  'pages/intro/HowPage': howScreen,
  'pages/try/PromptPage': promptScreen,
  'pages/try/StackPage': stackScreen,
  'pages/try/LearnAfterPage': learnAfterScreen,
  'pages/intro/ApproachesPage': approachesScreen,
  'pages/intro/WherePage': whereScreen,
  'pages/try/DilemmaPage': dilemmaScreen,
  'pages/try/RecapPage': recapScreen,
  'pages/try/QuizPage': quizScreen,
  'pages/try/ValuePage': valueScreen,
  'pages/try/AdoptChangePage': adoptChangeScreen,
  'pages/intro/IntroPage': introScreen,
  'pages/intro/ConceptPage': conceptScreen,
  'pages/intro/ComparePage': compareScreen,
  'pages/intro/OrderPage': orderScreen,
  'pages/lab/LabEntrancePage': labEntranceScreen,
  'pages/lab/LabCasePage': labCaseScreen,
  'pages/lab/LabChangePage': labChangeScreen,
  'pages/lab/LabBeforePage': labBeforeScreen,
  'pages/lab/LabSendPage': labSendScreen,
  'pages/lab/LabResultPage': labResultScreen,
  'pages/lab/LabRulesPage': labRulesScreen,
};

/** How long the first render waits at most for the records of a step opened straight from its address. */
const FIRST_RECORDS_LIMIT_MS = 1500;

/**
 * Reads the code of the screen at the first address before the first render, and the records its head shows (the case
 * list, and the latest run's comparison for the situation and the comparison) at the same time, so the first paint
 * already carries the step's headline. A slow answer holds the first render no longer than the limit; the screen then
 * shows its loading state as before. The other screens need nothing.
 */
export function preloadFirstScreen(location: Location, queryClient: QueryClient): Promise<void> {
  const module = firstScreenOf(location.pathname);
  if (module === null) {
    return Promise.resolve();
  }
  if (module !== 'pages/try/ExperiencePage') {
    return BY_MODULE[module].preload();
  }
  const match = /^\/try\/(attacker|owner)\/([a-z]+)$/.exec(location.pathname);
  const role = match?.[1] === 'owner' ? 'owner' : 'attacker';
  const step = match?.[2] ?? '';
  const records = [queryClient.prefetchQuery(labOptionsQuery)];
  if (step === 'scene' || step === 'compare') {
    const mode = modeOf(new URLSearchParams(location.search));
    records.push(queryClient.prefetchQuery(beforeSendQuery(CASES[role][mode], 1)));
  }
  const limit = new Promise<void>((done) => {
    setTimeout(done, FIRST_RECORDS_LIMIT_MS);
  });
  return Promise.all([experienceScreen.preload(), Promise.race([Promise.all(records), limit])]).then(
    () => undefined,
  );
}
