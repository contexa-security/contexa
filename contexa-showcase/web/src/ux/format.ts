/**
 * Numbers and times as the new screens write them (기획안 5.2 "숫자 · 시각"): thousands grouped by the language, a
 * recorded time as `YYYY-MM-DD HH:mm` in UTC with the local time kept for the tooltip, a latency in seconds with one
 * decimal. The zone word itself comes from the dictionary (`ux.time.zone`), so the Korean screens name it in words.
 */

const LOCALES: Readonly<Record<string, string>> = { ko: 'ko-KR', en: 'en-US' };

function locale(language: string): string {
  return LOCALES[language] ?? 'en-US';
}

export function formatNumber(value: number, language: string, fractionDigits?: number): string {
  const digits =
    fractionDigits === undefined
      ? {}
      : { minimumFractionDigits: fractionDigits, maximumFractionDigits: fractionDigits };
  return new Intl.NumberFormat(locale(language), digits).format(value);
}

function parsed(iso: string): Date | null {
  const time = new Date(iso);
  return Number.isNaN(time.getTime()) ? null : time;
}

/** `2026-10-31 15:24`, or a dash when the value is not a time. */
export function formatUtc(iso: string): string {
  const time = parsed(iso);
  return time ? time.toISOString().slice(0, 16).replace('T', ' ') : '—';
}

/** The same moment in the visitor's own zone, for the tooltip; empty when the value is not a time. */
export function localTime(iso: string, language: string): string {
  const time = parsed(iso);
  return time
    ? new Intl.DateTimeFormat(locale(language), { dateStyle: 'medium', timeStyle: 'short' }).format(time)
    : '';
}

/** Milliseconds as seconds with one decimal (`5959` → `6.0`); the unit word comes from `ux.time.seconds`. */
export function formatSeconds(milliseconds: number, language: string): string {
  return formatNumber(milliseconds / 1000, language, 1);
}

/**
 * A response time in seconds as the comparisons write it: three decimals under a second (a rule control's 0.027),
 * one above (Contexa's 10.2), so the two kinds of control stay readable side by side.
 */
export function formatDuration(milliseconds: number, language: string): string {
  return formatNumber(milliseconds / 1000, language, milliseconds < 1000 ? 3 : 1);
}
