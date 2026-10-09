import { describe, expect, it } from 'vitest';
import {
  FIRST_SCREEN_ADDRESSES,
  firstRecordsOf,
  firstScreenOf,
  type FirstScreenModule,
} from './src/firstScreens';
import { pickScript, type FirstScreenFiles } from './firstScreenPreload';

const MODULES = [
  ...new Set<FirstScreenModule>([
    'pages/try/TimingPage',
    'pages/try/FollowPage',
    ...Object.values(FIRST_SCREEN_ADDRESSES),
    'pages/try/ExperiencePage',
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
      ['/try/timing/try', ''],
      ['/try/follow', ''],
      ['/try/follow/end', ''],
      ['/try/attacker/scene', ''],
      ['/try/attacker/compare', '?mode=async'],
      ['/try/owner/scene', '?mode=async&lng=en'],
      ['/try/owner/result', ''],
      ['/try/attacker', ''],
      ['/', ''],
      ['/benchmark', ''],
      ['/adopt', ''],
    ];
    for (const [address, search] of addresses) {
      const module = firstScreenOf(address);
      const links = preloaded(address, search);
      expect(
        links.filter((link) => link.as === 'fetch').map((link) => link.href),
        address + search,
      ).toEqual(firstRecordsOf(address, search));
      expect(
        links.filter((link) => link.as !== 'fetch').map((link) => link.href),
        address + search,
      ).toEqual(module === null ? [] : [`/${module}.js`, `/${module}.css`]);
    }
  });

  it('preloads records as fetches, chunks as modules and style files as styles, with crossorigin like the bundle', () => {
    expect(preloaded('/try/owner/compare', '?mode=async')).toEqual([
      { rel: 'preload', as: 'fetch', crossOrigin: '', href: '/api/lab/options' },
      { rel: 'preload', as: 'fetch', crossOrigin: '', href: '/api/live/before/A3TA?step=1' },
      { rel: 'modulepreload', crossOrigin: '', href: '/pages/try/ExperiencePage.js' },
      { rel: 'preload', as: 'style', crossOrigin: '', href: '/pages/try/ExperiencePage.css' },
    ]);
  });
});
