/**
 * What the visitor sees when the gate in front of a new live run says no (deck p.20, p.28): the daily limit, a
 * pause of live runs, or a human check to complete again. Each leads on to stored real runs, never to a dead end.
 */
export type GateRefusal = 'dailyLimit' | 'paused' | 'turnstile' | 'error';

export function refusalOf(status: number, reason: string | null): GateRefusal {
  if (status === 429) {
    return 'dailyLimit';
  }
  // A full house, a spent daily allotment, or no template learned under the engine's current versions yet.
  if (status === 409 || (status === 503 && (reason === 'ALLOTMENT' || reason === 'TEMPLATE'))) {
    return 'paused';
  }
  if (status === 403 && reason?.startsWith('TURNSTILE')) {
    return 'turnstile';
  }
  return 'error';
}
