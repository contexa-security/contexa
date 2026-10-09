import type { Plugin } from 'vite';

/**
 * The rule src/i18n uses to pick the first language, as a script in index.html (same order, same storage key). The
 * preload carries crossorigin like the bundle's own module preloads, so the import that follows reuses it.
 */
function pickScript(chunks: Readonly<Record<string, string>>): string {
  return [
    '(function(){',
    `var m=${JSON.stringify(chunks)},h=function(v){return Object.prototype.hasOwnProperty.call(m,v)},`,
    'l=new URLSearchParams(location.search).get("lng");',
    'if(!h(l)){l=null;try{l=localStorage.getItem("showcase.language")}catch(e){}',
    'if(!h(l))l=navigator.language.toLowerCase().indexOf("ko")===0?"ko":"en"}',
    'var k=document.createElement("link");k.rel="modulepreload";k.crossOrigin="";k.href=m[l];document.head.appendChild(k)',
    '})();',
  ].join('');
}

/**
 * C-13: each language's dictionary is its own chunk and the first screen needs only one. This writes into index.html a
 * small script that picks the visitor's language by the same rule as src/i18n (the address's ?lng=, the remembered
 * language, the browser's language) and preloads that dictionary next to the application's code, so reading it adds no
 * round trip before the first paint.
 */
export function languagePreload(): Plugin {
  return {
    name: 'showcase-language-preload',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler(_html, context) {
        const chunks: Record<string, string> = {};
        for (const output of Object.values(context.bundle ?? {})) {
          const match =
            output.type === 'chunk' && output.facadeModuleId
              ? /[\\/]i18n[\\/](ko|en)\.json$/.exec(output.facadeModuleId)
              : null;
          if (match?.[1]) {
            chunks[match[1]] = `/${output.fileName}`;
          }
        }
        if (!chunks['ko'] || !chunks['en']) {
          throw new Error(`language preload: dictionary chunks not found (${Object.keys(chunks).join(', ')})`);
        }
        return [{ tag: 'script', children: pickScript(chunks), injectTo: 'head' }];
      },
    },
  };
}
