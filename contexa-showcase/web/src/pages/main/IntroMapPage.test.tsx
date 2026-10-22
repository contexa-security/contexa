import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import IntroMapPage from './IntroMapPage';

/** The measurement as the portal lists it: one scored run of each main case, Contexa right in each. */
const BENCHMARK = {
  scope: { runs: 44 },
  cases: ['S13', 'S13T', 'S16'].map((key) => ({ key, cells: { D: { right: 1, counted: 1 } } })),
};

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/benchmark': BENCHMARK,
      };
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/map']}>
        <Routes>
          <Route path="*" element={<IntroMapPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// Review before the guide videos (2026-10-21): 1-2, what the demo checks.
describe('the map of the demo', () => {
  it('says what a measured badge counts (B-11)', async () => {
    open();
    const badges = await screen.findAllByText(i18n.t('main.1-2.badge.measured', { right: 1, counted: 1 }));
    expect(badges).toHaveLength(3);
    expect(badges[0]).not.toHaveTextContent('1/1');
  });

  it('names the stolen-account theme by the three topics it holds (V-57)', () => {
    open();
    const outside = screen
      .getAllByRole('region')
      .find((region) => region.textContent?.startsWith(i18n.t('theme.outside.name')));
    expect(outside).toHaveTextContent(i18n.t('group.4'));
    expect(i18n.t('theme.outside.name')).toContain('정상 사용자');
  });

  it('promises one attack judgment before anything was sent (V-58) and whole words for counts (P-01, P-02)', () => {
    open();
    expect(i18n.t('main.1-2.3.try')).not.toContain('방금');
    expect(i18n.t('main.1-2.4.try')).not.toContain('PC에서 본인이');
    expect(i18n.t('main.1-2.5.try')).toContain('3건');
  });
});
