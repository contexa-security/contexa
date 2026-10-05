/** Returns the value or fails the test with a clear message; used instead of non-null assertions in tests. */
export function required<T>(value: T | null | undefined, what = 'value'): T {
  if (value === null || value === undefined) {
    throw new Error(`Missing ${what}`);
  }
  return value;
}
