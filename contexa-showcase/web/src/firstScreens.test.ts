import { QueryClient } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { firstRecordsOf } from './firstScreens';
import { preloadFirstScreen } from './screens';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('first screen records (C-13)', () => {
  it('are the records the application reads before a step first renders', async () => {
    for (const [pathname, search] of [
      ['/try/attacker/scene', ''],
      ['/try/attacker/compare', '?mode=async'],
      ['/try/owner/scene', '?mode=async'],
      ['/try/owner/predict', ''],
      ['/try/attacker/result', '?mode=async'],
      ['/intro', ''],
      ['/', ''],
    ] as const) {
      const asked: string[] = [];
      vi.stubGlobal('fetch', (input: RequestInfo | URL) => {
        asked.push(String(input));
        return Promise.resolve(
          new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
        );
      });
      await preloadFirstScreen({ pathname, search } as Location, new QueryClient());
      expect(asked, pathname + search).toEqual(firstRecordsOf(pathname, search));
    }
  });
});
