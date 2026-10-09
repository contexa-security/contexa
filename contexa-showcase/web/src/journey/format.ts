/**
 * One way to write each kind of number on every screen (plan 1절 7): the same value always reads the same. These only
 * format a value the server gave; they never compute one.
 */

/** Seconds from milliseconds: one decimal from a second on (7,964 ms → 8.0), two below it (53 ms → 0.05). */
export function seconds(ms: number): string {
  return ms >= 1000 ? (ms / 1000).toFixed(1) : (ms / 1000).toFixed(2);
}

/** Dollars: one significant digit below a cent (0.000598 → 0.0006), to the cent from there. */
export function dollars(value: number): string {
  return value >= 0.01 ? value.toFixed(2) : String(Number(value.toPrecision(1)));
}

/** A count with the language's thousands separator (4831 → 4,831). */
export function count(value: number, language: string): string {
  return value.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US');
}

/** A recorded instant as the source tag states it, in UTC ("2026-10-07 06:02:43"). */
export function utcTime(iso: string): string {
  return iso.replace('T', ' ').replace(/(\.\d+)?Z$/, '');
}
