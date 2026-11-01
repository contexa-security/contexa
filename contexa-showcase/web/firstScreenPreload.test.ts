import { describe, expect, it } from 'vitest';
import {
  FIRST_SCREEN_ADDRESSES,
  FIRST_SCREEN_PATTERNS,
  firstRecordsOf,
  firstScreenOf,
  type FirstScreenModule,
} from './src/firstScreens';
import { pickScript, type FirstScreenFiles } from './firstScreenPreload';

const MODULES = [
  ...new Set<FirstScreenModule>([
    ...Object.values(FIRST_SCREEN_ADDRESSES),
    ...FIRST_SCREEN_PATTERNS.map(([, module]) => module),
  ]),
];

/** One chunk and one style file per module, named after it, so a preloaded address tells which module was picked. */
const FILES: FirstScreenFiles = {
  files: MODULES.flatMap((module) => [`/${module}.js`, `/${module}.css`]),
  modules: Object.fromEntries(
    MODULES.map((module, at) => [module, { scripts: [at * 2], styles: [at * 2 + 1] }]),
  ) as FirstScreenFiles['modules'],
};

interface Link {
  rel?: string;
  as?: string;
  crossOrigin?: string;
  href?: string;
}

function preloaded(pathname: string, search = ''): Link[] {
  const added: Link[] = [];
  const page = { createElement: () => ({}), head: { appendChild: (link: Link) => added.push(link) } };
  new Function('location', 'document', pickScript(FILES))({ pathname, search }, page);
  return added;
}

describe('first screen preload (C-13)', () => {
  it('picks the same screen and records as the application for every address', () => {
    const addresses: [string, string][] = [
      ...Object.keys(FIRST_SCREEN_ADDRESSES).map((address): [string, string] => [address, '']),
      ['/simulate/person/S13/review', ''],
      ['/simulate/person/S16/review', '?lng=en'],
      ['/simulate/person/S13T/live', ''],
      ['/simulate/person/S13/result', '?tab=compare'],
      ['/simulate/person/S99/review', ''],
      ['/runs', ''],
      ['/attack/console', ''],
    ];
    for (const [address, search] of addresses) {
      const module = firstScreenOf(address);
      const links = preloaded(address, search);
      expect(
        links.filter((link) => link.as === 'fetch').map((link) => link.href),
        address + search,
      ).toEqual(firstRecordsOf(address));
      expect(
        links.filter((link) => link.as !== 'fetch').map((link) => link.href),
        address + search,
      ).toEqual(module === null ? [] : [`/${module}.js`, `/${module}.css`]);
    }
  });

  it('preloads records as fetches, chunks as modules and style files as styles, with crossorigin like the bundle', () => {
    expect(preloaded('/simulate/person/S13T/review')).toEqual([
      { rel: 'preload', as: 'fetch', crossOrigin: '', href: '/api/lab/options' },
      { rel: 'preload', as: 'fetch', crossOrigin: '', href: '/api/live/before/S13T?step=1' },
      { rel: 'modulepreload', crossOrigin: '', href: '/ux/pages/simulate/person/ReviewPage.js' },
      { rel: 'preload', as: 'style', crossOrigin: '', href: '/ux/pages/simulate/person/ReviewPage.css' },
    ]);
  });
});
