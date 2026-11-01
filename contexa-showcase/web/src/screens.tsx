import type { QueryClient } from '@tanstack/react-query';
import { lazy, type ComponentType } from 'react';
import { beforeSendQuery } from './api/anatomy';
import { labOptionsQuery } from './api/lab';
import { FIRST_RECORDS, firstScreenOf, type FirstScreenModule } from './firstScreens';
import { dictionaryComplete } from './i18n';

/**
 * A screen outside the first screens is drawn once the rest of the dictionary is in (FC-4, dictionarySplit.ts): its
 * words are not in the part the first screen reads. If the rest cannot be read, the screen is drawn anyway.
 */
export function withDictionary<T>(load: () => Promise<T>): () => Promise<T> {
  return () => Promise.all([load(), dictionaryComplete().catch(() => undefined)]).then(([module]) => module);
}

/**
 * A screen whose code loads when it is first opened (P5-FE-01), which a visitor can also open straight from a shared
 * link. On such a first load its code is read before the first render, so the screen never waits behind the loading
 * fallback, which React keeps for at least 300 ms once shown (C-13).
 */
export function preloadable<P extends object>(load: () => Promise<{ default: ComponentType<P> }>) {
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

// The first screens (UX-R1, DEC-14): the start of the demo and the threat simulation's steps. Their words are in the
// first part of the dictionary (dictionarySplit.ts), so they are drawn without waiting for the rest.
export const homeScreen = preloadable(() => import('./ux/pages/home/HomePage'));
export const pickScreen = preloadable(() => import('./ux/pages/simulate/person/PickPage'));
export const reviewScreen = preloadable(() => import('./ux/pages/simulate/person/ReviewPage'));
export const liveScreen = preloadable(() => import('./ux/pages/simulate/person/LivePage'));
export const resultScreen = preloadable(() => import('./ux/pages/simulate/person/ResultPage'));

/** Each first screen's code, by the module the shared rule (src/firstScreens.ts) names. */
const BY_MODULE: Readonly<Record<FirstScreenModule, { readonly preload: () => Promise<void> }>> = {
  'ux/pages/home/HomePage': homeScreen,
  'ux/pages/simulate/person/PickPage': pickScreen,
  'ux/pages/simulate/person/ReviewPage': reviewScreen,
  'ux/pages/simulate/person/LivePage': liveScreen,
  'ux/pages/simulate/person/ResultPage': resultScreen,
};

/** How long the first render waits at most for the records of a screen opened straight from its address. */
const FIRST_RECORDS_LIMIT_MS = 1500;

/**
 * Reads the code of the screen at the first address before the first render, and the records the request review
 * shows first (the case list and the comparison before sending) at the same time, so the first paint already carries
 * the request. A slow answer holds the first render no longer than the limit; the screen then shows its loading state.
 */
export function preloadFirstScreen(location: Location, queryClient: QueryClient): Promise<void> {
  const module = firstScreenOf(location.pathname);
  if (module === null) {
    return Promise.resolve();
  }
  const match = new RegExp(FIRST_RECORDS.pattern).exec(location.pathname);
  if (!match?.[1]) {
    return BY_MODULE[module].preload();
  }
  const records = [
    queryClient.prefetchQuery(labOptionsQuery),
    queryClient.prefetchQuery(beforeSendQuery(match[1], 1)),
  ];
  const limit = new Promise<void>((done) => {
    setTimeout(done, FIRST_RECORDS_LIMIT_MS);
  });
  return Promise.all([BY_MODULE[module].preload(), Promise.race([Promise.all(records), limit])]).then(
    () => undefined,
  );
}
