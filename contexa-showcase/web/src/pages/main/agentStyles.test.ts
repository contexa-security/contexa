import { describe, expect, it } from 'vitest';

/** Node's file reader, typed here: the app's type set has no Node types, and vitest runs these tests in Node. */
type ReadFile = (path: string, encoding: 'utf-8') => string;
const FS = 'node:fs';
const { readFileSync } = (await import(/* @vite-ignore */ FS)) as { readonly readFileSync: ReadFile };

/**
 * Layout rules of the agent timeline found by the full-screen audit of stage S2 (2026-10-27, 6-6 in English at 390 px:
 * "one letter alone"). jsdom lays nothing out, so the stylesheet's rules are read.
 */
const css = readFileSync('src/pages/main/AgentPages.module.css', 'utf-8').replace(/\r\n/g, '\n');

/** The declarations of a rule of the stylesheet, by its selector as written. */
function rule(selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const found = new RegExp(`(?:^|\\n)${escaped} \\{([^}]*)\\}`).exec(css)?.[1];
  if (found === undefined) {
    throw new Error(`missing ${selector}`);
  }
  return found;
}

describe('the request address in the agent timeline', () => {
  it('stays on one line, so a narrow screen scrolls the table and never leaves one letter of an address alone', () => {
    expect(rule('.requestPath')).toContain('white-space: nowrap;');
    expect(rule('.requestPath')).not.toContain('overflow-wrap');
  });
});
