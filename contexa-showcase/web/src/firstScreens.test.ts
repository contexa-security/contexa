import { QueryClient } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { firstRecordsOf } from './firstScreens';
import { preloadFirstScreen } from './screens';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('first screen records (C-13, UX-R1 DEC-14)', () => {
  it('are the records the application reads before a first screen renders', async () => {
    for (const pathname of [
      '/simulate/person/S13/review',
      '/simulate/person/S16/review',
      '/simulate/person/S13/live',
      '/simulate/person',
      '/',
      '/runs',
    ]) {
      const asked: string[] = [];
      vi.stubGlobal('fetch', (input: RequestInfo | URL) => {
        asked.push(String(input));
        return Promise.resolve(
          new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
        );
      });
      await preloadFirstScreen({ pathname, search: '' } as Location, new QueryClient());
      expect(asked, pathname).toEqual(firstRecordsOf(pathname));
    }
  });

  it('name the case list and the scenario of the request review', () => {
    expect(firstRecordsOf('/simulate/person/S13T/review')).toEqual([
      '/api/lab/options',
      '/api/live/before/S13T?step=1',
    ]);
    expect(firstRecordsOf('/simulate/person/S99/review')).toEqual([]);
  });
});
