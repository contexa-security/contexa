import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { brotliCompressSync, constants } from 'node:zlib';
import type { Plugin } from 'vite';

/** Text files the portal serves, and the size below which compressing does not pay (the portal's own threshold). */
const TEXT = /\.(?:html|js|css|svg|json)$/;
const MIN_BYTES = 1024;

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
}

/**
 * C-13: writes a Brotli copy (.br) next to every text file of the production bundle. The portal serves the copy to a
 * browser that accepts it (Spring's EncodedResourceResolver), which is about a fifth smaller than the gzip the portal
 * compresses on the fly; anything else still gets the original.
 */
export function precompress(): Plugin {
  let outDir = 'dist';
  return {
    name: 'showcase-precompress',
    apply: 'build',
    configResolved(config) {
      outDir = resolve(config.root, config.build.outDir);
    },
    closeBundle() {
      for (const path of files(outDir)) {
        const content = readFileSync(path);
        if (TEXT.test(path) && content.length >= MIN_BYTES) {
          writeFileSync(
            `${path}.br`,
            brotliCompressSync(content, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }),
          );
        }
      }
    },
  };
}
