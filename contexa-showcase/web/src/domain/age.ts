/** How long ago a stored real run was made: just now, whole hours (below two days), or whole days. */
export interface Age {
  readonly unit: 'now' | 'hours' | 'days';
  readonly n: number;
}

const HOUR = 3_600_000;

/**
 * The age of a stored run for its "N hours ago" badge (docs/agent Agent중심-화면 AC-4a, AC-5, D-7). Below an hour it is
 * "now"; the portal's clock may be a little ahead of the browser's, so a run from the future is "now" too, never negative.
 */
export function ageOf(ranAt: string, now: number): Age {
  const hours = Math.floor((now - Date.parse(ranAt)) / HOUR);
  if (hours < 1) {
    return { unit: 'now', n: 0 };
  }
  return hours < 48 ? { unit: 'hours', n: hours } : { unit: 'days', n: Math.floor(hours / 24) };
}
