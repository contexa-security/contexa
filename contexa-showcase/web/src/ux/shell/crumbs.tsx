import { useState, type ReactNode } from 'react';
import type { Crumb } from '../ui';
import { CrumbContext } from './crumbState';

/** Holds the screen's own places for the breadcrumb (crumbState.ts). */
export function CrumbProvider({ children }: { readonly children: ReactNode }) {
  const [extra, setExtra] = useState<readonly Crumb[]>([]);
  return <CrumbContext.Provider value={{ extra, setExtra }}>{children}</CrumbContext.Provider>;
}
