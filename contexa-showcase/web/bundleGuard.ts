import type { Plugin } from 'vite';

/**
 * Deck p.37 (P5-SEC-06): the visitor bundle names no internal address, port, database or operator path. The dev
 * server's proxy target lives in vite.config.ts and never reaches the bundle; this guard keeps it that way.
 */
export const INTERNAL_MARKERS: readonly { name: string; pattern: RegExp }[] = [
  {
    name: 'private or loopback address',
    pattern: /\b(?:127\.\d{1,3}|10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b/,
  },
  { name: 'localhost with a port', pattern: /\blocalhost:\d+/ },
  { name: 'showcase port', pattern: /:(?:191[89]\d|29180|46432)\b/ },
  { name: 'showcase database', pattern: /\bshowcase_(?:portal|engine|vector|work)/ },
  { name: 'internal workload path', pattern: /\/internal\// },
  { name: 'operator path', pattern: /\/ops\// },
  { name: 'internal signature header', pattern: /X-Showcase-/i },
  { name: 'database URL', pattern: /\bjdbc:/ },
];

export function findInternalMarkers(text: string): string[] {
  return INTERNAL_MARKERS.filter((marker) => marker.pattern.test(text)).map((marker) => marker.name);
}

/** Fails the production build when any emitted script, style or page carries an internal marker. */
export function internalAddressGuard(): Plugin {
  return {
    name: 'showcase-internal-address-guard',
    apply: 'build',
    generateBundle(_options, bundle) {
      const problems: string[] = [];
      for (const output of Object.values(bundle)) {
        const text =
          output.type === 'chunk' ? output.code : typeof output.source === 'string' ? output.source : null;
        if (text === null) {
          continue;
        }
        for (const name of findInternalMarkers(text)) {
          problems.push(`${output.fileName}: ${name}`);
        }
      }
      if (problems.length > 0) {
        this.error(`The visitor bundle carries internal markers: ${problems.join('; ')}`);
      }
    },
  };
}
