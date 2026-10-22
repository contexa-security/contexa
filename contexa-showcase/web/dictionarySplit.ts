import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import type { Plugin } from 'vite';
import { FIRST_SCREEN_ADDRESSES } from './src/firstScreens';

/**
 * FC-4: each language's dictionary in two parts. The first part holds the words the main flow can show (the
 * application's entry and every screen of the main flow, with everything they import); it is read before the first
 * paint. The rest (the "learn more" topics, the lab, the benchmark, the decision details and the other spaces) is read
 * after it, and the screens that use it wait for it (src/i18n). Both parts come from the one dictionary file, so the
 * copy keeps one source.
 */

export type DictionaryPart = 'first' | 'rest';

const VIRTUAL = 'virtual:dictionary/';
const RESOLVED = '\0dictionary-';
const LANGUAGES = ['ko', 'en'] as const;

/** A static import or re-export of a relative module; dynamic imports (the screens loaded later) are left out. */
const IMPORT = /^\s*(?:import|export)\s[^'"]*?from\s+['"](\.[^'"]+)['"]|^\s*import\s+['"](\.[^'"]+)['"]/gm;
/** A quoted string or a template literal. */
const STRING = /'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"|`((?:[^`\\]|\\.)*)`/g;
/** A string that names a branch of keys (at least two segments), such as 'main.2-1'. */
const BRANCH = /^[a-z][\w-]*(?:\.[\w-]+)+$/;
const PLURAL = /_(?:zero|one|two|few|many|other)$/;

function resolveImport(from: string, spec: string): string | null {
  const target = resolve(dirname(from), spec);
  for (const candidate of [
    target,
    `${target}.ts`,
    `${target}.tsx`,
    join(target, 'index.ts'),
    join(target, 'index.tsx'),
  ]) {
    if (/\.(tsx?|json)$/.test(candidate) && existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

/** The source files the given modules reach through static imports (JSON files included: they carry keys too). */
function reached(starts: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const todo = [...starts];
  while (todo.length > 0) {
    const file = todo.pop() as string;
    if (seen.has(file)) {
      continue;
    }
    seen.add(file);
    if (file.endsWith('.json')) {
      continue;
    }
    for (const match of readFileSync(file, 'utf8').matchAll(IMPORT)) {
      const found = resolveImport(file, match[1] ?? match[2] ?? '');
      if (found) {
        todo.push(found);
      }
    }
  }
  return seen;
}

/** The main flow's entry points: the application's entry and the screen of every main-flow address and "/more". */
function mainFlowStarts(web: string): string[] {
  const route = JSON.parse(readFileSync(join(web, 'src/journey/route.json'), 'utf8')) as readonly {
    readonly path: string;
  }[];
  const addresses = new Set([...route.map((screen) => screen.path), '/more']);
  const screens = Object.entries(FIRST_SCREEN_ADDRESSES)
    .filter(([address]) => addresses.has(address))
    .map(([, module]) => resolveImport(join(web, 'src', 'x'), `./${module}`))
    .filter((file): file is string => file !== null);
  return [join(web, 'src/main.tsx'), ...screens];
}

/**
 * The keys of the first part: a key the main flow's sources name whole (or by its plural's base), a key under a
 * branch they name ('main.2-1' → 'main.2-1.title'), or a key that starts with the fixed head of a template they build
 * a key from (`main.${number}.cta` → 'main.').
 */
export function firstKeys(web: string, keys: readonly string[]): Set<string> {
  const whole = new Set<string>();
  const heads = new Set<string>();
  for (const file of reached(mainFlowStarts(web))) {
    for (const match of readFileSync(file, 'utf8').matchAll(STRING)) {
      const template = match[3];
      if (template !== undefined && template.includes('${')) {
        const head = template.slice(0, template.indexOf('${'));
        if (head.length > 0) {
          heads.add(head);
        }
        continue;
      }
      whole.add(template ?? match[1] ?? match[2] ?? '');
    }
  }
  const branches = [...whole].filter((value) => BRANCH.test(value)).map((value) => `${value}.`);
  const fixed = [...heads];
  return new Set(
    keys.filter(
      (key) =>
        whole.has(key) ||
        whole.has(key.replace(PLURAL, '')) ||
        branches.some((branch) => key.startsWith(branch)) ||
        fixed.some((head) => key.startsWith(head)),
    ),
  );
}

/** One part of a language's dictionary. */
export function dictionaryPart(
  web: string,
  language: string,
  part: DictionaryPart,
): Readonly<Record<string, string>> {
  const dictionary = JSON.parse(readFileSync(join(web, 'src/i18n', `${language}.json`), 'utf8')) as Record<
    string,
    string
  >;
  // Both languages carry the same keys (dictionaries.test.ts); the split follows the Korean one's order.
  const first = firstKeys(web, Object.keys(dictionary));
  return Object.fromEntries(
    Object.entries(dictionary).filter(([key]) => first.has(key) === (part === 'first')),
  );
}

/** The two parts as modules: `virtual:dictionary/{ko|en}/{first|rest}`. */
export function dictionarySplit(web: string): Plugin {
  return {
    name: 'showcase-dictionary-split',
    resolveId(id) {
      const match = id.startsWith(VIRTUAL) ? /^virtual:dictionary\/(ko|en)\/(first|rest)$/.exec(id) : null;
      return match ? `${RESOLVED}${match[1]}-${match[2]}` : null;
    },
    load(id) {
      const match = id.startsWith(RESOLVED) ? /^\0dictionary-(ko|en)-(first|rest)$/.exec(id) : null;
      if (!match?.[1] || !match[2]) {
        return null;
      }
      for (const language of LANGUAGES) {
        this.addWatchFile(join(web, 'src/i18n', `${language}.json`));
      }
      const part = dictionaryPart(web, match[1], match[2] as DictionaryPart);
      return `export default ${JSON.stringify(part)};`;
    },
  };
}
