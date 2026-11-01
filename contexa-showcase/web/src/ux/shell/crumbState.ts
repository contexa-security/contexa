import { createContext, useContext, useEffect } from 'react';
import type { Crumb } from '../ui';

/**
 * The places below the menu item a screen is on (a step, a run, a tab), which the top bar's breadcrumb adds after the
 * menu group and the menu item. A screen names them with useCrumbs; they go when the screen goes.
 */
export interface CrumbState {
  readonly extra: readonly Crumb[];
  readonly setExtra: (crumbs: readonly Crumb[]) => void;
}

export const CrumbContext = createContext<CrumbState>({ extra: [], setExtra: () => undefined });

export function useExtraCrumbs(): readonly Crumb[] {
  return useContext(CrumbContext).extra;
}

/** The places after the menu item on this screen, in order; the last one is the current page. */
export function useCrumbs(crumbs: readonly Crumb[]): void {
  const { setExtra } = useContext(CrumbContext);
  const key = JSON.stringify(crumbs);
  useEffect(() => {
    setExtra(JSON.parse(key) as Crumb[]);
    return () => setExtra([]);
  }, [key, setExtra]);
}
