import type { ReactNode } from 'react';

/**
 * A sentence with the pieces a pattern finds (a code like HX-310, a date and time) wrapped in their own span, so the
 * span's class keeps each one whole on a line (L-24, L-27). The words are not changed; the rest stays plain text.
 */
export function keepWhole(text: string, pattern: RegExp, className: string | undefined): ReactNode[] {
  const nodes: ReactNode[] = [];
  let from = 0;
  for (const match of text.matchAll(new RegExp(pattern.source, `${pattern.flags.replace('g', '')}g`))) {
    const at = match.index;
    if (at > from) {
      nodes.push(text.slice(from, at));
    }
    nodes.push(
      <span key={at} className={className}>
        {match[0]}
      </span>,
    );
    from = at + match[0].length;
  }
  if (from < text.length) {
    nodes.push(text.slice(from));
  }
  return nodes;
}
