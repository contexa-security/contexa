import type { BusinessOutcome } from './verdict';

/** How many approaches stopped a request, let it through, or did neither (held it or could not decide). */
export interface Tally {
  readonly stopped: number;
  readonly passed: number;
  readonly other: number;
}

/** The one-sentence conclusion of a scene counts business outcomes: was the data stopped or did it leave. */
export function tally(layers: readonly { readonly outcome: BusinessOutcome }[]): Tally {
  let stopped = 0;
  let passed = 0;
  let other = 0;
  for (const layer of layers) {
    if (layer.outcome === 'STOPPED' || layer.outcome === 'CUT') {
      stopped += 1;
    } else if (layer.outcome === 'DELIVERED') {
      passed += 1;
    } else {
      other += 1;
    }
  }
  return { stopped, passed, other };
}
