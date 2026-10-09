import type { IndexHtmlTransformContext, Plugin } from 'vite';
import {
  FIRST_RECORDS,
  FIRST_SCREEN_ADDRESSES,
  FIRST_SCREEN_PATTERNS,
  FIRST_SCREEN_PREFIXES,
  TRY_CASES,
  type FirstScreenModule,
} from './src/firstScreens';

type Bundle = NonNullable<IndexHtmlTransformContext['bundle']>;

/** The files the browser needs for each first screen, as indexes into one list of file addresses. */
export interface FirstScreenFiles {
  readonly files: readonly string[];
  readonly modules: Readonly<
    Record<FirstScreenModule, { readonly scripts: number[]; readonly styles: number[] }>
  >;
}

/** Adds a chunk's files to `scripts` and `styles`: the chunk, its style files, and those of the chunks it imports. */
function collect(bundle: Bundle, fileName: string, scripts: Set<string>, styles: Set<string>): void {
  const output = bundle[fileName];
  if (output?.type !== 'chunk' || scripts.has(fileName)) {
    return;
  }
  scripts.add(fileName);
  for (const style of output.viteMetadata?.importedCss ?? []) {
    styles.add(style);
  }
  for (const imported of output.imports) {
    collect(bundle, imported, scripts, styles);
  }
}

/**
 * For every module the shared rule names, the chunk files and the style files its first render needs beyond what
 * index.html already loads (the entry chunk and everything it imports).
 */
export function firstScreenFiles(bundle: Bundle): FirstScreenFiles {
  const loaded = new Set<string>();
  for (const output of Object.values(bundle)) {
    if (output.type === 'chunk' && output.isEntry) {
      collect(bundle, output.fileName, loaded, loaded);
    }
  }
  const files: string[] = [];
  const indexOf = (fileName: string) => {
    const address = `/${fileName}`;
    const found = files.indexOf(address);
    return found >= 0 ? found : files.push(address) - 1;
  };
  const named: FirstScreenModule[] = [
    ...FIRST_SCREEN_PREFIXES.map(([, module]) => module),
    ...Object.values(FIRST_SCREEN_ADDRESSES),
    ...FIRST_SCREEN_PATTERNS.map(([, module]) => module),
  ];
  const modules = {} as Record<FirstScreenModule, { scripts: number[]; styles: number[] }>;
  for (const module of new Set(named)) {
    const chunk = Object.values(bundle).find(
      (output) =>
        output.type === 'chunk' && output.facadeModuleId?.replace(/\\/g, '/').endsWith(`/src/${module}.tsx`),
    );
    if (chunk?.type !== 'chunk') {
      throw new Error(`first screen preload: no chunk for ${module}`);
    }
    const scripts = new Set<string>();
    const styles = new Set<string>();
    collect(bundle, chunk.fileName, scripts, styles);
    modules[module] = {
      scripts: [...scripts].filter((file) => !loaded.has(file)).map(indexOf),
      styles: [...styles].filter((file) => !loaded.has(file)).map(indexOf),
    };
  }
  return { files, modules };
}

/**
 * The script index.html runs before the application: it picks the first screen by the same rule as
 * src/firstScreens.ts (beginnings, then whole addresses, then patterns) and preloads that screen's chunks and style
 * files with crossorigin like the bundle's own preload links, so the module and style links the import adds later
 * reuse them instead of reading them again. A try step's records are preloaded the same way as fetches (crossorigin:
 * the same-origin credentials the application's own reads use, so its read takes the preloaded answer).
 */
export function pickScript({ files, modules }: FirstScreenFiles): string {
  const order = Object.keys(modules) as FirstScreenModule[];
  const at = (module: FirstScreenModule) => order.indexOf(module);
  const rules = {
    p: FIRST_SCREEN_PREFIXES.map(([start, module]) => [start, at(module)]),
    a: Object.fromEntries(
      Object.entries(FIRST_SCREEN_ADDRESSES).map(([address, module]) => [address, at(module)]),
    ),
    r: FIRST_SCREEN_PATTERNS.map(([source, module]) => [source, at(module)]),
  };
  const needs = order.map((module) => [modules[module].scripts, modules[module].styles]);
  const records = { ...FIRST_RECORDS, cases: TRY_CASES };
  return [
    '(function(){',
    `var F=${JSON.stringify(files)},M=${JSON.stringify(needs)},S=${JSON.stringify(rules)},a=location.pathname,i=-1,j;`,
    `var R=${JSON.stringify(records)},m=new RegExp(R.pattern).exec(a);`,
    'if(m){var q=R.always.slice();if(R.compared.indexOf(m[2])>=0)q.push(R.comparison.replace("{case}",',
    'encodeURIComponent(R.cases[m[1]][new URLSearchParams(location.search).get("mode")==="async"?"async":"sync"])));',
    'q.forEach(function(h){var k=document.createElement("link");k.rel="preload";k.as="fetch";k.crossOrigin="";',
    'k.href=h;document.head.appendChild(k)})}',
    'for(j=0;i<0&&j<S.p.length;j++)if(a.indexOf(S.p[j][0])===0)i=S.p[j][1];',
    'if(i<0&&Object.prototype.hasOwnProperty.call(S.a,a))i=S.a[a];',
    'for(j=0;i<0&&j<S.r.length;j++)if(new RegExp(S.r[j][0]).test(a))i=S.r[j][1];',
    'if(i<0)return;',
    'var l=function(s,h){var k=document.createElement("link");k.rel=s?"preload":"modulepreload";',
    'if(s)k.as="style";k.crossOrigin="";k.href=F[h];document.head.appendChild(k)};',
    'M[i][0].forEach(function(h){l(false,h)});M[i][1].forEach(function(h){l(true,h)});',
    '})();',
  ].join('');
}

/**
 * C-13: a screen opened straight from its address used to start reading its own code only after the application's
 * code had arrived and run, one more round of requests before the first paint. This writes into index.html the shared
 * first-screen rule with each screen's files, so the browser reads them together with the application's code.
 */
export function firstScreenPreload(): Plugin {
  return {
    name: 'showcase-first-screen-preload',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler(_html, context) {
        if (!context.bundle) {
          throw new Error('first screen preload: no bundle');
        }
        return [{ tag: 'script', children: pickScript(firstScreenFiles(context.bundle)), injectTo: 'head' }];
      },
    },
  };
}
