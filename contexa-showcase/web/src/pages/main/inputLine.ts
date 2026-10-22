import type { TFunction } from 'i18next';

/** The portal's key of a comparison with the usual pattern (InputComparison): the dimension after it. */
const DIMENSION = 'dim.';

/**
 * One engine input of 4-3 as a line: an input the engine received under its own label stays as it is
 * ({@code ApprovalMissing: true}); a comparison with the usual pattern, which the portal keys by its dimension and
 * writes with the engine's membership label ({@code dim.device} and {@code Safari/18 on MAC · false}), is named in plain
 * words with that label in words: {@code 기기: Safari/18 on MAC · 평소와 다름}. A label that is no yes or no (the engine's
 * reason it could not compare) stays as the engine wrote it.
 */
export function inputLine(t: TFunction, key: string, value: string | null): string {
  if (!key.startsWith(DIMENSION)) {
    return `${key}: ${value ?? '-'}`;
  }
  const name = t(key, { defaultValue: key.slice(DIMENSION.length) });
  if (value === null) {
    return `${name}: -`;
  }
  const at = value.lastIndexOf(' · ');
  const label = at < 0 ? null : value.slice(at + 3);
  const state = label === 'false' ? 'dim.different' : label === 'true' ? 'dim.same' : null;
  return state === null ? `${name}: ${value}` : `${name}: ${value.slice(0, at)} · ${t(state)}`;
}
